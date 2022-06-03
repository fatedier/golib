package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"github.com/fatedier/golib/pool"
	"io"
	"sync"
)

const (
	AeadMaxTextLength = (1 << 14) - 1
)

type AeadWriter struct {
	S     cipher.AEAD
	W     io.Writer
	nonce []byte
	mu    sync.Mutex
}

func NewAeadWriter(S cipher.AEAD, W io.Writer) *AeadWriter {
	return &AeadWriter{
		S:     S,
		W:     W,
		nonce: make([]byte, S.NonceSize()),
	}
}

func (w *AeadWriter) Write(src []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.write(src)
}

func (w *AeadWriter) write(src []byte) (n int, err error) {
	var nBase int
	if len(src) > AeadMaxTextLength {
		handleLength := len(src) % AeadMaxTextLength
		if handleLength == 0 {
			handleLength = AeadMaxTextLength
		}
		if nBase, err = w.write(src[:len(src)-handleLength]); err != nil {
			return nBase, err
		}
		src = src[len(src)-handleLength:]
	}
	c := pool.GetBuf(2 + w.S.Overhead() + len(src) + w.S.Overhead())
	defer pool.PutBuf(c)
	// put the length into the first two bytes, then the overhead
	binary.BigEndian.PutUint16(c[:2], uint16(len(src)))
	w.S.Seal(c[:0], w.nonce, c[:2], nil)
	BytesIncLittleEndian(w.nonce)

	// encrypt the plaintext
	w.S.Seal(c[2+w.S.Overhead():2+w.S.Overhead()], w.nonce, src, nil)
	BytesIncLittleEndian(w.nonce)

	// write the encrypted text
	nWrite, err := w.W.Write(c)
	if nWrite != len(c) && err == nil { // should never happen
		err = io.ErrShortWrite
	}
	return nBase + len(src), nil
}

// Close closes the underlying Writer and returns its Close return value, if the Writer
// is also an io.Closer. Otherwise it returns nil.
func (w *AeadWriter) Close() error {
	if c, ok := w.W.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func BytesIncLittleEndian(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}
