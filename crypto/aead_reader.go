package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"github.com/fatedier/golib/pool"
	"io"
	"sync"
)

type AeadReader struct {
	S     cipher.AEAD
	R     io.Reader
	nonce []byte
	buf   []byte
	start int
	mu    sync.Mutex
}

func NewAeadReader(S cipher.AEAD, R io.Reader) *AeadReader {
	return &AeadReader{
		S:     S,
		R:     R,
		nonce: make([]byte, S.NonceSize()),
	}
}

// Read reads an AEAD chunk at a time
func (r *AeadReader) Read(dst []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buf != nil {
		n = copy(dst, r.buf[r.start:])
		r.start += n
		if r.start >= len(r.buf) {
			pool.PutBuf(r.buf)
			r.buf = nil
		}
		return n, nil
	}
	bLength := pool.GetBuf(2 + r.S.Overhead())
	defer pool.PutBuf(bLength)
	if _, err = io.ReadFull(r.R, bLength); err != nil {
		return 0, err
	}
	// decrypt the length of the chunk
	if bLength, err = r.S.Open(bLength[:0], r.nonce, bLength, nil); err != nil {
		return 0, err
	}
	BytesIncLittleEndian(r.nonce)

	u16Length := binary.BigEndian.Uint16(bLength)
	buf := pool.GetBuf(int(u16Length) + r.S.Overhead())
	defer func() {
		if err != nil {
			pool.PutBuf(buf)
		}
	}()
	if _, err = io.ReadFull(r.R, buf); err != nil {
		return 0, err
	}
	// decrypt the encrypted text
	if buf, err = r.S.Open(buf[:0], r.nonce, buf, nil); err != nil {
		return 0, err
	}
	BytesIncLittleEndian(r.nonce)
	// store the unread bytes
	n = copy(dst, buf)
	if n < len(buf) {
		r.buf = buf
		r.start = n
	} else {
		pool.PutBuf(buf)
	}
	return n, nil
}
