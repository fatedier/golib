// Copyright 2026 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	AEADAlgorithmAES256GCM         AEADAlgorithm = "aes-256-gcm"
	AEADAlgorithmXChaCha20Poly1305 AEADAlgorithm = "xchacha20-poly1305"

	AEADKeySize               = 32
	DefaultAEADMaxPayloadSize = 64 * 1024
)

const (
	aeadFrameHeaderSize     = 4
	aeadMaxAESGCMFrameCount = uint64(1) << 32
)

type AEADAlgorithm string

// AEADStreamOptions configures the framed AEAD stream reader and writer.
// Key must be a raw 32-byte AEAD key. Callers are responsible for deriving it
// from application secrets before constructing the stream.
//
// The AEAD stream authenticates each frame and its order, but it does not
// authenticate end-of-stream. A clean EOF on a frame boundary is treated as
// normal stream termination. Protocols that need object/file truncation
// detection must authenticate a total length or final record at a higher layer.
//
// For AES-256-GCM, this package enforces a per-stream limit of 2^32 frames.
// This is a local limit only; callers that reuse a key across multiple streams
// or directions must enforce the global per-key limit themselves or derive
// independent keys.
type AEADStreamOptions struct {
	Algorithm      AEADAlgorithm
	Key            []byte
	MaxPayloadSize int
}

// AEADStreamWriter encrypts plaintext into a framed AEAD stream.
//
// The wire format is:
//
//	stream nonce || repeated frame
//
// Each frame is:
//
//	uint32 ciphertext length || AEAD ciphertext and tag
//
// The stream nonce is sent in cleartext and seeds the first frame nonce. Each
// subsequent frame increments that nonce by one. Each frame authenticates the
// stream nonce and frame length header as AAD, which binds frame order to the
// stream. AEADStreamWriter is not safe for concurrent use by multiple
// goroutines. Once Write returns an error, the writer remembers it and returns
// the same error from subsequent Write calls.
type AEADStreamWriter struct {
	w              io.Writer
	aead           cipher.AEAD
	maxPayloadSize int
	maxFrameCount  uint64
	frameCount     uint64
	// streamNonce is filled from the stream header and stays fixed for AAD binding;
	// nonce is the mutable frame nonce.
	streamNonce []byte
	nonce       []byte
	scratch     []byte
	aadScratch  []byte
	headerSent  bool
	err         error
}

// NewAEADStreamWriter returns an io.Writer that encrypts bytes into framed AEAD records.
// It is intended for connection-oriented streams. Close/final-record semantics
// are not part of this writer; see AEADStreamOptions for end-of-stream behavior.
func NewAEADStreamWriter(w io.Writer, opts AEADStreamOptions) (*AEADStreamWriter, error) {
	aead, maxPayloadSize, err := newAEAD(opts)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, err
	}

	return &AEADStreamWriter{
		w:              w,
		aead:           aead,
		maxPayloadSize: maxPayloadSize,
		maxFrameCount:  maxAEADStreamFrameCount(opts.Algorithm),
		streamNonce:    append([]byte(nil), nonce...),
		nonce:          nonce,
		scratch:        make([]byte, 0, aeadFrameHeaderSize+maxPayloadSize+aead.Overhead()),
		aadScratch:     make([]byte, 0, aead.NonceSize()+aeadFrameHeaderSize),
	}, nil
}

func (w *AEADStreamWriter) Write(p []byte) (nRet int, errRet error) {
	if w.err != nil {
		return 0, w.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	for len(p) > 0 {
		chunkSize := min(len(p), w.maxPayloadSize)
		if err := w.writeFrame(p[:chunkSize]); err != nil {
			w.err = err
			return nRet, err
		}
		nRet += chunkSize
		p = p[chunkSize:]
	}
	return nRet, nil
}

func (w *AEADStreamWriter) writeFrame(plaintext []byte) error {
	if w.maxFrameCount > 0 && w.frameCount >= w.maxFrameCount {
		return fmt.Errorf("aead stream frame count limit %d exceeded", w.maxFrameCount)
	}

	if !w.headerSent {
		if err := writeFull(w.w, w.nonce); err != nil {
			return err
		}
		w.headerSent = true
	}

	var header [aeadFrameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(plaintext)+w.aead.Overhead()))
	out := w.scratch[:0]
	out = append(out, header[:]...)
	aad := buildAEADStreamFrameAAD(w.aadScratch, w.streamNonce, header[:])
	out = w.aead.Seal(out, w.nonce, plaintext, aad)
	if !incrementNonce(w.nonce) {
		return fmt.Errorf("aead stream frame counter exhausted")
	}
	w.frameCount++
	return writeFull(w.w, out)
}

// AEADStreamReader decrypts the framed AEAD stream produced by AEADStreamWriter.
//
// It authenticates each frame and its order using the stream nonce, frame
// header, and incrementing frame nonce. Truncation inside a frame is returned as
// an error from the underlying reader, but EOF at a frame boundary is treated as
// normal stream termination and does not authenticate end-of-stream.
// AEADStreamReader is not safe for concurrent use by multiple goroutines.
type AEADStreamReader struct {
	r              io.Reader
	aead           cipher.AEAD
	maxPayloadSize int
	maxFrameCount  uint64
	frameCount     uint64
	// streamNonce stays fixed for AAD binding; nonce is the mutable frame nonce.
	streamNonce []byte
	nonce       []byte
	scratch     []byte
	aadScratch  []byte
	buf         []byte
	headerRead  bool
	err         error
}

// NewAEADStreamReader returns an io.Reader that decrypts framed AEAD records.
// It validates frame authentication and ordering, but EOF at a frame boundary is
// returned as a normal EOF; see AEADStreamOptions for end-of-stream behavior.
func NewAEADStreamReader(r io.Reader, opts AEADStreamOptions) (*AEADStreamReader, error) {
	aead, maxPayloadSize, err := newAEAD(opts)
	if err != nil {
		return nil, err
	}
	return &AEADStreamReader{
		r:              r,
		aead:           aead,
		maxPayloadSize: maxPayloadSize,
		maxFrameCount:  maxAEADStreamFrameCount(opts.Algorithm),
		nonce:          make([]byte, aead.NonceSize()),
		scratch:        make([]byte, maxPayloadSize+aead.Overhead()),
		aadScratch:     make([]byte, 0, aead.NonceSize()+aeadFrameHeaderSize),
	}, nil
}

func (r *AEADStreamReader) Read(p []byte) (nRet int, errRet error) {
	if len(p) == 0 {
		return 0, nil
	}

	for len(r.buf) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if err := r.readFrame(); err != nil {
			r.err = err
			return 0, err
		}
	}

	nRet = copy(p, r.buf)
	r.buf = r.buf[nRet:]
	return nRet, nil
}

func (r *AEADStreamReader) readFrame() error {
	if !r.headerRead {
		if _, err := io.ReadFull(r.r, r.nonce); err != nil {
			return err
		}
		r.streamNonce = append([]byte(nil), r.nonce...)
		r.headerRead = true
	}

	var header [aeadFrameHeaderSize]byte
	if _, err := io.ReadFull(r.r, header[:]); err != nil {
		return err
	}
	if r.maxFrameCount > 0 && r.frameCount >= r.maxFrameCount {
		return fmt.Errorf("aead stream frame count limit %d exceeded", r.maxFrameCount)
	}

	ciphertextLen := binary.BigEndian.Uint32(header[:])
	minCiphertextLen := uint64(r.aead.Overhead())
	maxCiphertextLen := uint64(r.maxPayloadSize) + uint64(r.aead.Overhead())
	if uint64(ciphertextLen) < minCiphertextLen {
		return fmt.Errorf("aead stream ciphertext length %d is smaller than overhead %d", ciphertextLen, minCiphertextLen)
	}
	if uint64(ciphertextLen) > maxCiphertextLen {
		return fmt.Errorf("aead stream ciphertext length %d exceeds limit %d", ciphertextLen, maxCiphertextLen)
	}

	ciphertext := r.scratch[:ciphertextLen]
	if _, err := io.ReadFull(r.r, ciphertext); err != nil {
		return err
	}

	aad := buildAEADStreamFrameAAD(r.aadScratch, r.streamNonce, header[:])
	plaintext, err := r.aead.Open(ciphertext[:0], r.nonce, ciphertext, aad)
	if err != nil {
		return err
	}
	if !incrementNonce(r.nonce) {
		return fmt.Errorf("aead stream frame counter exhausted")
	}
	r.frameCount++
	r.buf = plaintext
	return nil
}

func newAEAD(opts AEADStreamOptions) (cipher.AEAD, int, error) {
	if len(opts.Key) != AEADKeySize {
		return nil, 0, fmt.Errorf("aead key must be %d bytes", AEADKeySize)
	}

	var (
		aead cipher.AEAD
		err  error
	)
	switch opts.Algorithm {
	case AEADAlgorithmAES256GCM:
		var block cipher.Block
		block, err = aes.NewCipher(opts.Key)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	case AEADAlgorithmXChaCha20Poly1305:
		aead, err = chacha20poly1305.NewX(opts.Key)
	default:
		return nil, 0, fmt.Errorf("unsupported aead algorithm: %s", opts.Algorithm)
	}
	if err != nil {
		return nil, 0, err
	}

	maxPayloadSize := opts.MaxPayloadSize
	if maxPayloadSize == 0 {
		maxPayloadSize = DefaultAEADMaxPayloadSize
	}
	if maxPayloadSize < 0 {
		return nil, 0, fmt.Errorf("aead max payload size must not be negative")
	}
	if uint64(maxPayloadSize)+uint64(aead.Overhead()) > math.MaxUint32 {
		return nil, 0, fmt.Errorf("aead max payload size %d is too large", maxPayloadSize)
	}
	return aead, maxPayloadSize, nil
}

func maxAEADStreamFrameCount(algorithm AEADAlgorithm) uint64 {
	if algorithm == AEADAlgorithmAES256GCM {
		return aeadMaxAESGCMFrameCount
	}
	return 0
}

// incrementNonce increments nonce in place and reports whether it did not wrap.
func incrementNonce(nonce []byte) bool {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			return true
		}
	}
	return false
}

func buildAEADStreamFrameAAD(dst []byte, streamNonce []byte, header []byte) []byte {
	dst = dst[:0]
	dst = append(dst, streamNonce...)
	dst = append(dst, header...)
	return dst
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			if err != nil {
				return fmt.Errorf("invalid write count %d: %w", n, err)
			}
			return fmt.Errorf("invalid write count %d", n)
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
