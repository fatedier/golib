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
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

var aeadTestAlgorithms = []AEADAlgorithm{
	AEADAlgorithmAES256GCM,
	AEADAlgorithmXChaCha20Poly1305,
}

func TestAEADStreamRoundTrip(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			text := []byte("Go is expressive, concise, clean, and efficient.")
			var buffer bytes.Buffer

			writer, err := NewAEADStreamWriter(&buffer, testAEADOptions(algorithm, 0))
			require.NoError(t, err)
			n, err := writer.Write(text)
			require.NoError(t, err)
			require.Equal(t, len(text), n)

			reader, err := NewAEADStreamReader(&buffer, testAEADOptions(algorithm, 0))
			require.NoError(t, err)
			out, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Equal(t, text, out)
		})
	}
}

func TestAEADStreamEmptyWriteWritesNothing(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			var buffer bytes.Buffer

			writer, err := NewAEADStreamWriter(&buffer, testAEADOptions(algorithm, 0))
			require.NoError(t, err)
			n, err := writer.Write(nil)
			require.NoError(t, err)
			require.Zero(t, n)
			require.Empty(t, buffer.Bytes())

			n, err = writer.Write([]byte{})
			require.NoError(t, err)
			require.Zero(t, n)
			require.Empty(t, buffer.Bytes())
		})
	}
}

func TestAEADStreamSplitsLargePayload(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			payload := bytes.Repeat([]byte("abcdefgh"), 20*1024)
			var buffer bytes.Buffer

			opts := testAEADOptions(algorithm, 1024)
			writer, err := NewAEADStreamWriter(&buffer, opts)
			require.NoError(t, err)
			n, err := writer.Write(payload)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)

			reader, err := NewAEADStreamReader(&buffer, opts)
			require.NoError(t, err)
			out, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Equal(t, payload, out)
		})
	}
}

func TestAEADStreamConsecutiveWritesUseDistinctNonces(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			opts := testAEADOptions(algorithm, 0)
			var buffer bytes.Buffer
			writer, err := NewAEADStreamWriter(&buffer, opts)
			require.NoError(t, err)
			_, err = writer.Write([]byte("a"))
			require.NoError(t, err)
			firstFrameNonce := append([]byte(nil), writer.nonce...)
			_, err = writer.Write([]byte("b"))
			require.NoError(t, err)

			require.NotEqual(t, firstFrameNonce, writer.nonce)
		})
	}
}

func TestAEADStreamSmallReadBuffer(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			payload := bytes.Repeat([]byte("hello world"), 128)
			var buffer bytes.Buffer

			writer, err := NewAEADStreamWriter(&buffer, testAEADOptions(algorithm, 64))
			require.NoError(t, err)
			_, err = writer.Write(payload)
			require.NoError(t, err)

			reader, err := NewAEADStreamReader(&buffer, testAEADOptions(algorithm, 64))
			require.NoError(t, err)
			readBuf := make([]byte, 7)
			var out bytes.Buffer
			for {
				n, err := reader.Read(readBuf)
				if n > 0 {
					out.Write(readBuf[:n])
				}
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
			}
			require.Equal(t, payload, out.Bytes())
		})
	}
}

func TestAEADStreamMidFrameTruncationFails(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			encrypted := encryptedAEADPayload(t, algorithm, []byte("secret"))
			truncated := encrypted[:len(encrypted)-1]

			reader, err := NewAEADStreamReader(bytes.NewReader(truncated), testAEADOptions(algorithm, 0))
			require.NoError(t, err)
			_, err = io.ReadAll(reader)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	}
}

func TestAEADStreamZeroPayloadFrameOnWire(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			opts := testAEADOptions(algorithm, 0)
			var buffer bytes.Buffer
			writer, err := NewAEADStreamWriter(&buffer, opts)
			require.NoError(t, err)
			err = writer.writeFrame(nil)
			require.NoError(t, err)
			_, err = writer.Write([]byte("secret"))
			require.NoError(t, err)

			reader, err := NewAEADStreamReader(bytes.NewReader(buffer.Bytes()), opts)
			require.NoError(t, err)
			out, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Equal(t, []byte("secret"), out)
		})
	}
}

func TestAEADStreamWrongKeyFails(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			var buffer bytes.Buffer

			writer, err := NewAEADStreamWriter(&buffer, testAEADOptions(algorithm, 0))
			require.NoError(t, err)
			_, err = writer.Write([]byte("secret"))
			require.NoError(t, err)

			opts := testAEADOptions(algorithm, 0)
			opts.Key = []byte("fedcba9876543210fedcba9876543210")
			reader, err := NewAEADStreamReader(&buffer, opts)
			require.NoError(t, err)
			_, err = io.ReadAll(reader)
			require.Error(t, err)
		})
	}
}

func TestAEADStreamTamperedStreamHeaderFails(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			encrypted := encryptedAEADPayload(t, algorithm, []byte("secret"))
			encrypted[0] ^= 0x01

			reader, err := NewAEADStreamReader(bytes.NewReader(encrypted), testAEADOptions(algorithm, 0))
			require.NoError(t, err)
			_, err = io.ReadAll(reader)
			require.Error(t, err)
		})
	}
}

func TestAEADStreamTamperedCiphertextFails(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			encrypted := encryptedAEADPayload(t, algorithm, []byte("secret"))
			encrypted[len(encrypted)-1] ^= 0x01

			reader, err := NewAEADStreamReader(bytes.NewReader(encrypted), testAEADOptions(algorithm, 0))
			require.NoError(t, err)
			_, err = io.ReadAll(reader)
			require.Error(t, err)
		})
	}
}

func TestAEADStreamOutOfOrderFrameFails(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			var buffer bytes.Buffer
			opts := testAEADOptions(algorithm, 0)
			writer, err := NewAEADStreamWriter(&buffer, opts)
			require.NoError(t, err)
			_, err = writer.Write([]byte("a"))
			require.NoError(t, err)
			_, err = writer.Write([]byte("b"))
			require.NoError(t, err)

			nonceSize, overhead := testAEADParams(t, algorithm)
			frameSize := aeadFrameHeaderSize + 1 + overhead
			encrypted := buffer.Bytes()
			streamHeader := append([]byte(nil), encrypted[:nonceSize]...)
			frame1 := encrypted[nonceSize : nonceSize+frameSize]
			frame2 := encrypted[nonceSize+frameSize:]
			swapped := streamHeader
			swapped = append(swapped, frame2...)
			swapped = append(swapped, frame1...)

			reader, err := NewAEADStreamReader(bytes.NewReader(swapped), opts)
			require.NoError(t, err)
			_, err = io.ReadAll(reader)
			require.Error(t, err)
		})
	}
}

func TestAEADStreamPrefixDeletionFails(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			var buffer bytes.Buffer
			opts := testAEADOptions(algorithm, 0)
			writer, err := NewAEADStreamWriter(&buffer, opts)
			require.NoError(t, err)
			_, err = writer.Write([]byte("a"))
			require.NoError(t, err)
			_, err = writer.Write([]byte("b"))
			require.NoError(t, err)

			nonceSize, overhead := testAEADParams(t, algorithm)
			frameSize := aeadFrameHeaderSize + 1 + overhead
			encrypted := buffer.Bytes()
			secondFrame := encrypted[nonceSize+frameSize:]

			forgedStreamHeader := make([]byte, nonceSize)
			copy(forgedStreamHeader, encrypted[:nonceSize])
			require.True(t, incrementNonce(forgedStreamHeader))
			forged := forgedStreamHeader
			forged = append(forged, secondFrame...)

			reader, err := NewAEADStreamReader(bytes.NewReader(forged), opts)
			require.NoError(t, err)
			_, err = io.ReadAll(reader)
			require.Error(t, err)
		})
	}
}

func TestAEADStreamFrameSizeLimit(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			encrypted := encryptedAEADPayload(t, algorithm, bytes.Repeat([]byte("x"), 16))
			opts := testAEADOptions(algorithm, 8)
			reader, err := NewAEADStreamReader(bytes.NewReader(encrypted), opts)
			require.NoError(t, err)
			_, err = io.ReadAll(reader)
			require.ErrorContains(t, err, "exceeds limit")
		})
	}
}

func TestAEADStreamInvalidOptions(t *testing.T) {
	_, err := NewAEADStreamWriter(io.Discard, AEADStreamOptions{
		Algorithm: AEADAlgorithmAES256GCM,
		Key:       []byte("short"),
	})
	require.ErrorContains(t, err, "aead key must be")

	_, err = NewAEADStreamWriter(io.Discard, AEADStreamOptions{
		Algorithm: AEADAlgorithm("unknown"),
		Key:       testAEADKey(),
	})
	require.ErrorContains(t, err, "unsupported aead algorithm")

	_, err = NewAEADStreamWriter(io.Discard, AEADStreamOptions{
		Algorithm:      AEADAlgorithmXChaCha20Poly1305,
		Key:            testAEADKey(),
		MaxPayloadSize: -1,
	})
	require.ErrorContains(t, err, "must not be negative")
}

func TestAEADStreamWriterUsesFullWrites(t *testing.T) {
	for _, algorithm := range aeadTestAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			var writer shortWriter
			streamWriter, err := NewAEADStreamWriter(&writer, testAEADOptions(algorithm, 0))
			require.NoError(t, err)
			_, err = streamWriter.Write([]byte("secret"))
			require.NoError(t, err)

			reader, err := NewAEADStreamReader(bytes.NewReader(writer.Bytes()), testAEADOptions(algorithm, 0))
			require.NoError(t, err)
			out, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Equal(t, []byte("secret"), out)
		})
	}
}

func TestAEADStreamFrameCountLimits(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := NewAEADStreamWriter(&buffer, testAEADOptions(AEADAlgorithmAES256GCM, 0))
	require.NoError(t, err)
	require.Equal(t, aeadMaxAESGCMFrameCount, writer.maxFrameCount)

	buffer.Reset()
	writer, err = NewAEADStreamWriter(&buffer, testAEADOptions(AEADAlgorithmXChaCha20Poly1305, 0))
	require.NoError(t, err)
	require.Zero(t, writer.maxFrameCount)
}

func TestAEADStreamAESGCMWriterFrameCountLimit(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := NewAEADStreamWriter(&buffer, testAEADOptions(AEADAlgorithmAES256GCM, 0))
	require.NoError(t, err)
	writer.maxFrameCount = 1

	n, err := writer.Write([]byte("a"))
	require.NoError(t, err)
	require.Equal(t, 1, n)

	n, err = writer.Write([]byte("b"))
	require.ErrorContains(t, err, "frame count limit")
	require.Equal(t, 0, n)
}

func TestAEADStreamAESGCMReaderFrameCountLimit(t *testing.T) {
	opts := testAEADOptions(AEADAlgorithmAES256GCM, 1)
	var buffer bytes.Buffer
	writer, err := NewAEADStreamWriter(&buffer, opts)
	require.NoError(t, err)
	_, err = writer.Write([]byte("ab"))
	require.NoError(t, err)

	reader, err := NewAEADStreamReader(bytes.NewReader(buffer.Bytes()), opts)
	require.NoError(t, err)
	reader.maxFrameCount = 1

	out, err := io.ReadAll(reader)
	require.ErrorContains(t, err, "frame count limit")
	require.Equal(t, []byte("a"), out)
}

func TestAEADStreamAESGCMReaderCleanEOFAtFrameCountLimit(t *testing.T) {
	encrypted := encryptedAEADPayload(t, AEADAlgorithmAES256GCM, []byte("a"))

	reader, err := NewAEADStreamReader(bytes.NewReader(encrypted), testAEADOptions(AEADAlgorithmAES256GCM, 0))
	require.NoError(t, err)
	reader.maxFrameCount = 1

	out, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, []byte("a"), out)
}

func TestAEADStreamWriteFullPreservesInvalidWriterError(t *testing.T) {
	writerErr := errors.New("writer failed")
	err := writeFull(invalidCountWriter{n: -1, err: writerErr}, []byte("secret"))
	require.ErrorContains(t, err, "invalid write count -1")
	require.ErrorIs(t, err, writerErr)
}

func encryptedAEADPayload(t *testing.T, algorithm AEADAlgorithm, payload []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := NewAEADStreamWriter(&buffer, testAEADOptions(algorithm, 0))
	require.NoError(t, err)
	_, err = writer.Write(payload)
	require.NoError(t, err)
	return buffer.Bytes()
}

func testAEADOptions(algorithm AEADAlgorithm, maxPayloadSize int) AEADStreamOptions {
	return AEADStreamOptions{
		Algorithm:      algorithm,
		Key:            testAEADKey(),
		MaxPayloadSize: maxPayloadSize,
	}
}

func testAEADKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func testAEADParams(t *testing.T, algorithm AEADAlgorithm) (nonceSize, overhead int) {
	t.Helper()
	aead, _, err := newAEAD(testAEADOptions(algorithm, 0))
	require.NoError(t, err)
	return aead.NonceSize(), aead.Overhead()
}

type shortWriter struct {
	bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:len(p)/2]
	}
	return w.Buffer.Write(p)
}

type invalidCountWriter struct {
	n   int
	err error
}

func (w invalidCountWriter) Write([]byte) (int, error) {
	return w.n, w.err
}
