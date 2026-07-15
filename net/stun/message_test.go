package stun

import (
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type testAttribute struct {
	typ     uint16
	value   []byte
	padding []byte
}

func makeTestMessage(typ uint16, id transactionID, attributes ...testAttribute) []byte {
	length := 0
	for _, attribute := range attributes {
		length += attributeHeaderSize + (len(attribute.value)+attributeAlignment-1)&^(attributeAlignment-1)
	}
	packet := make([]byte, messageHeaderSize, messageHeaderSize+length)
	binary.BigEndian.PutUint16(packet[0:2], typ)
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	binary.BigEndian.PutUint32(packet[4:8], magicCookie)
	copy(packet[8:20], id[:])

	for _, attribute := range attributes {
		start := len(packet)
		paddedLength := (len(attribute.value) + attributeAlignment - 1) &^ (attributeAlignment - 1)
		packet = append(packet, make([]byte, attributeHeaderSize+paddedLength)...)
		binary.BigEndian.PutUint16(packet[start:start+2], attribute.typ)
		binary.BigEndian.PutUint16(packet[start+2:start+4], uint16(len(attribute.value)))
		copy(packet[start+4:], attribute.value)
		copy(packet[start+4+len(attribute.value):], attribute.padding)
	}
	return packet
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(strings.ReplaceAll(value, " ", ""))
	require.NoError(t, err)
	return data
}

func TestBuildBindingRequestGolden(t *testing.T) {
	id := transactionID{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	request := buildBindingRequest(id)
	require.Equal(t,
		"000100002112a442000102030405060708090a0b",
		hex.EncodeToString(request[:]),
	)
}

func TestMessageBinaryCodecOwnershipAndRoundTrip(t *testing.T) {
	id := transactionID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	want := makeTestMessage(bindingSuccess, id,
		testAttribute{typ: 0x7777, value: []byte{1}, padding: []byte{0xaa, 0xbb, 0xcc}},
		testAttribute{typ: attrMappedAddress, value: plainAddressValue(net.ParseIP("192.0.2.10"), 3478)},
	)
	input := append([]byte(nil), want...)

	var message Message
	var unmarshaler encoding.BinaryUnmarshaler = &message
	require.NoError(t, unmarshaler.UnmarshalBinary(input))
	require.True(t, message.IsBindingResponse())
	require.False(t, message.IsBindingRequest())
	require.Equal(t, [12]byte(id), message.TransactionID())

	for i := range input {
		input[i] ^= 0xff
	}
	var marshaler encoding.BinaryMarshaler = message
	first, err := marshaler.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, want, first)

	first[0] ^= 0xff
	second, err := message.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, want, second)
}

func TestMessageReuseAndFailedUnmarshal(t *testing.T) {
	firstID := transactionID{1, 2, 3}
	secondID := transactionID{4, 5, 6}
	first := makeTestMessage(bindingSuccess, firstID)
	second := buildBindingRequest(secondID)

	var message Message
	require.NoError(t, message.UnmarshalBinary(first))
	require.True(t, message.IsBindingResponse())
	require.NoError(t, message.UnmarshalBinary(second[:]))
	require.True(t, message.IsBindingRequest())
	require.Equal(t, [12]byte(secondID), message.TransactionID())

	before, err := message.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, second[:], before)
	malformed := append(append([]byte(nil), second[:]...), 0, 0, 0, 0)
	require.ErrorIs(t, message.UnmarshalBinary(malformed), ErrMalformedResponse)
	after, err := message.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, before, after)

	var zero Message
	_, err = zero.MarshalBinary()
	require.Error(t, err)
	var nilMessage *Message
	require.Error(t, nilMessage.UnmarshalBinary(first))
}

func TestParseRFC5769BindingResponses(t *testing.T) {
	tests := []struct {
		name       string
		packet     string
		expectedIP string
	}{
		{
			name: "IPv4",
			packet: "0101003c2112a442b7e7a701bc34d686fa87dfae" +
				"8022000b7465737420766563746f7220" +
				"002000080001a147e112a643" +
				"000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7" +
				"80280004c07d4c96",
			expectedIP: "192.0.2.1",
		},
		{
			name: "IPv6",
			packet: "010100482112a442b7e7a701bc34d686fa87dfae" +
				"8022000b7465737420766563746f7220" +
				"002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9" +
				"00080014a382954e4be67bf11784c97c8292c275bfe3ed41" +
				"80280004c8fb0b4c",
			expectedIP: "2001:db8:1234:5678:11:2233:4455:6677",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := decodeHex(t, tt.packet)
			m, err := parseMessage(packet)
			require.NoError(t, err)
			response, err := decodeBindingSuccess(m)
			require.NoError(t, err)
			require.NotNil(t, response.MappedAddr)
			require.True(t, response.MappedAddr.IP.Equal(net.ParseIP(tt.expectedIP)))
			require.Equal(t, 32853, response.MappedAddr.Port)
			require.Nil(t, response.OtherAddr)
		})
	}
}

func TestParseMessageIntentionallySkipsUnknownAttributesInBothRanges(t *testing.T) {
	id := transactionID{1, 2, 3}
	// This minimal client intentionally skips unknown comprehension-required and
	// comprehension-optional attributes to preserve its explicit compatibility contract.
	packet := makeTestMessage(bindingSuccess, id,
		testAttribute{typ: 0x7777, value: []byte{0xaa}, padding: []byte{0xde, 0xad, 0xbe}},
		testAttribute{typ: 0x8777, value: []byte{0xbb}},
		testAttribute{typ: attrMappedAddress, value: plainAddressValue(net.ParseIP("192.0.2.9"), 3478)},
	)
	m, err := parseMessage(packet)
	require.NoError(t, err)
	response, err := decodeBindingSuccess(m)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.9:3478", response.MappedAddr.String())
}

func TestParseMessageRejectsMalformedFraming(t *testing.T) {
	id := transactionID{1, 2, 3}
	valid := makeTestMessage(bindingSuccess, id)

	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty", packet: nil},
		{name: "short header", packet: valid[:messageHeaderSize-1]},
		{name: "leading type bits", packet: func() []byte {
			packet := append([]byte(nil), valid...)
			packet[0] |= 0xc0
			return packet
		}()},
		{name: "bad cookie", packet: func() []byte {
			packet := append([]byte(nil), valid...)
			packet[4] ^= 0xff
			return packet
		}()},
		{name: "non-aligned declared length", packet: func() []byte {
			packet := append(append([]byte(nil), valid...), 0, 0)
			binary.BigEndian.PutUint16(packet[2:4], 2)
			return packet
		}()},
		{name: "truncated datagram", packet: func() []byte {
			packet := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(packet[2:4], 4)
			return packet
		}()},
		{name: "trailing bytes", packet: append(append([]byte(nil), valid...), 0, 0, 0, 0)},
		{name: "truncated attribute value", packet: func() []byte {
			packet := makeTestMessage(bindingSuccess, id, testAttribute{typ: 0x7777})
			binary.BigEndian.PutUint16(packet[22:24], 4)
			return packet
		}()},
		{name: "truncated attribute padding", packet: func() []byte {
			packet := makeTestMessage(bindingSuccess, id, testAttribute{typ: 0x7777, value: []byte{1}})
			return packet[:len(packet)-1]
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseMessage(tt.packet)
			require.ErrorIs(t, err, ErrMalformedResponse)
		})
	}
}

func TestIsCorrelatedResponse(t *testing.T) {
	id := transactionID{1, 2, 3}
	valid := makeTestMessage(bindingSuccess, id)
	require.True(t, isCorrelatedResponse(valid, id))
	require.False(t, isCorrelatedResponse(valid[:19], id))

	wrongType := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(wrongType[0:2], bindingRequest)
	require.False(t, isCorrelatedResponse(wrongType, id))

	wrongCookie := append([]byte(nil), valid...)
	wrongCookie[4] ^= 1
	require.False(t, isCorrelatedResponse(wrongCookie, id))

	wrongID := append([]byte(nil), valid...)
	wrongID[8] ^= 1
	require.False(t, isCorrelatedResponse(wrongID, id))
}

func TestNewTransactionIDEntropyError(t *testing.T) {
	wantErr := errors.New("entropy failed")
	_, err := newTransactionID(errorReader{err: wantErr})
	require.ErrorIs(t, err, wantErr)
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
