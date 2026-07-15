package stun

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func plainAddressValue(ip net.IP, port int) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		value := make([]byte, 4+net.IPv4len)
		value[1] = addressFamilyIPv4
		binary.BigEndian.PutUint16(value[2:4], uint16(port))
		copy(value[4:], ip4)
		return value
	}
	value := make([]byte, 4+net.IPv6len)
	value[1] = addressFamilyIPv6
	binary.BigEndian.PutUint16(value[2:4], uint16(port))
	copy(value[4:], ip.To16())
	return value
}

func xorAddressValue(ip net.IP, port int, id transactionID) []byte {
	value := plainAddressValue(ip, port)
	binary.BigEndian.PutUint16(value[2:4], binary.BigEndian.Uint16(value[2:4])^uint16(magicCookie>>16))
	var mask [net.IPv6len]byte
	binary.BigEndian.PutUint32(mask[:4], magicCookie)
	copy(mask[4:], id[:])
	for i := 4; i < len(value); i++ {
		value[i] ^= mask[i-4]
	}
	return value
}

func TestDecodeLegacyAndModernAddresses(t *testing.T) {
	id := transactionID{0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae}

	t.Run("legacy IPv4", func(t *testing.T) {
		packet := makeTestMessage(bindingSuccess, id,
			testAttribute{typ: attrMappedAddress, value: plainAddressValue(net.ParseIP("198.51.100.7"), 40000)},
			testAttribute{typ: attrChangedAddress, value: plainAddressValue(net.ParseIP("203.0.113.8"), 3479)},
		)
		m, err := parseMessage(packet)
		require.NoError(t, err)
		response, err := decodeBindingSuccess(m)
		require.NoError(t, err)
		require.Equal(t, "198.51.100.7:40000", response.MappedAddr.String())
		require.Equal(t, "203.0.113.8:3479", response.OtherAddr.String())
	})

	t.Run("modern precedence", func(t *testing.T) {
		packet := makeTestMessage(bindingSuccess, id,
			testAttribute{typ: attrMappedAddress, value: plainAddressValue(net.ParseIP("192.0.2.1"), 1000)},
			testAttribute{typ: attrXORMappedAddress, value: xorAddressValue(net.ParseIP("198.51.100.2"), 2000, id)},
			testAttribute{typ: attrChangedAddress, value: plainAddressValue(net.ParseIP("192.0.2.3"), 3000)},
			testAttribute{typ: attrOtherAddress, value: plainAddressValue(net.ParseIP("198.51.100.4"), 4000)},
		)
		m, err := parseMessage(packet)
		require.NoError(t, err)
		response, err := decodeBindingSuccess(m)
		require.NoError(t, err)
		require.Equal(t, "198.51.100.2:2000", response.MappedAddr.String())
		require.Equal(t, "198.51.100.4:4000", response.OtherAddr.String())
	})

	t.Run("plain IPv6", func(t *testing.T) {
		mappedIP := net.ParseIP("2001:db8::10")
		otherIP := net.ParseIP("2001:db8::20")
		packet := makeTestMessage(bindingSuccess, id,
			testAttribute{typ: attrMappedAddress, value: plainAddressValue(mappedIP, 5000)},
			testAttribute{typ: attrOtherAddress, value: plainAddressValue(otherIP, 5001)},
		)
		m, err := parseMessage(packet)
		require.NoError(t, err)
		response, err := decodeBindingSuccess(m)
		require.NoError(t, err)
		require.True(t, response.MappedAddr.IP.Equal(mappedIP))
		require.Equal(t, 5000, response.MappedAddr.Port)
		require.True(t, response.OtherAddr.IP.Equal(otherIP))
		require.Equal(t, 5001, response.OtherAddr.Port)
	})

	t.Run("missing addresses", func(t *testing.T) {
		m, err := parseMessage(makeTestMessage(bindingSuccess, id))
		require.NoError(t, err)
		response, err := decodeBindingSuccess(m)
		require.NoError(t, err)
		require.Nil(t, response.MappedAddr)
		require.Nil(t, response.OtherAddr)
	})
}

func TestFirstDuplicateWinsAndAllTLVsRemainStructural(t *testing.T) {
	id := transactionID{1, 2, 3}
	packet := makeTestMessage(bindingSuccess, id,
		testAttribute{typ: attrMappedAddress, value: plainAddressValue(net.ParseIP("192.0.2.1"), 1000)},
		testAttribute{typ: attrMappedAddress, value: plainAddressValue(net.ParseIP("192.0.2.2"), 2000)},
	)
	m, err := parseMessage(packet)
	require.NoError(t, err)
	response, err := decodeBindingSuccess(m)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1:1000", response.MappedAddr.String())

	malformedDuplicate := append([]byte(nil), packet...)
	secondOffset := messageHeaderSize + attributeHeaderSize + len(plainAddressValue(net.IPv4zero, 0))
	binary.BigEndian.PutUint16(malformedDuplicate[secondOffset+2:secondOffset+4], 100)
	_, err = parseMessage(malformedDuplicate)
	require.ErrorIs(t, err, ErrMalformedResponse)
}

func TestPreferredAddressControlsValidation(t *testing.T) {
	id := transactionID{1, 2, 3}

	t.Run("valid preferred ignores malformed fallback", func(t *testing.T) {
		packet := makeTestMessage(bindingSuccess, id,
			testAttribute{typ: attrMappedAddress, value: []byte{0, addressFamilyIPv4, 0, 1}},
			testAttribute{typ: attrXORMappedAddress, value: xorAddressValue(net.ParseIP("192.0.2.8"), 8080, id)},
		)
		m, err := parseMessage(packet)
		require.NoError(t, err)
		response, err := decodeBindingSuccess(m)
		require.NoError(t, err)
		require.Equal(t, "192.0.2.8:8080", response.MappedAddr.String())
	})

	t.Run("malformed preferred does not fall back", func(t *testing.T) {
		packet := makeTestMessage(bindingSuccess, id,
			testAttribute{typ: attrMappedAddress, value: plainAddressValue(net.ParseIP("192.0.2.9"), 9090)},
			testAttribute{typ: attrXORMappedAddress, value: []byte{0, addressFamilyIPv4, 0, 1}},
		)
		m, err := parseMessage(packet)
		require.NoError(t, err)
		_, err = decodeBindingSuccess(m)
		require.ErrorIs(t, err, ErrMalformedResponse)
	})
}

func TestDecodeAddressErrors(t *testing.T) {
	id := transactionID{}

	_, err := decodeAddress([]byte{0, addressFamilyIPv4, 0}, id, false)
	require.ErrorIs(t, err, ErrMalformedResponse)

	_, err = decodeAddress([]byte{0, 0x7f, 0, 1}, id, false)
	require.ErrorIs(t, err, ErrUnsupportedAddressFamily)

	_, err = decodeAddress([]byte{0, addressFamilyIPv6, 0, 1, 1, 2, 3, 4}, id, false)
	require.ErrorIs(t, err, ErrMalformedResponse)
}

func TestDecodeAddressIgnoresReservedOctet(t *testing.T) {
	id := transactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	tests := []struct {
		name string
		ip   net.IP
		port int
		xor  bool
	}{
		{name: "plain IPv4", ip: net.ParseIP("198.51.100.10"), port: 41000},
		{name: "plain IPv6", ip: net.ParseIP("2001:db8::10"), port: 41001},
		{name: "XOR IPv4", ip: net.ParseIP("198.51.100.11"), port: 41002, xor: true},
		{name: "XOR IPv6", ip: net.ParseIP("2001:db8::11"), port: 41003, xor: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := plainAddressValue(tt.ip, tt.port)
			if tt.xor {
				value = xorAddressValue(tt.ip, tt.port, id)
			}
			value[0] = 0xff

			address, err := decodeAddress(value, id, tt.xor)
			require.NoError(t, err)
			require.True(t, address.IP.Equal(tt.ip))
			require.Equal(t, tt.port, address.Port)
		})
	}
}

func TestDecodeBindingError(t *testing.T) {
	id := transactionID{1, 2, 3}
	packet := makeTestMessage(bindingError, id,
		testAttribute{typ: 0x7777, value: []byte("ignored")},
		testAttribute{typ: attrErrorCode, value: []byte{0, 0, 4, 20, 'U', 'n', 'k', 'n', 'o', 'w', 'n'}},
		testAttribute{typ: attrErrorCode, value: []byte{0, 0, 5, 0}},
	)
	m, err := parseMessage(packet)
	require.NoError(t, err)
	err = decodeBindingError(m)
	var responseErr *ResponseError
	require.ErrorAs(t, err, &responseErr)
	require.Equal(t, 420, responseErr.Code)
	require.Equal(t, "Unknown", responseErr.Reason)
	require.Equal(t, "STUN binding error 420: Unknown", responseErr.Error())
}

func TestDecodeBindingErrorIgnoresReservedBits(t *testing.T) {
	id := transactionID{1, 2, 3}
	packet := makeTestMessage(bindingError, id, testAttribute{
		typ:   attrErrorCode,
		value: []byte{0xab, 0xcd, 0xfc, 20, 'U', 'n', 'k', 'n', 'o', 'w', 'n'},
	})
	m, err := parseMessage(packet)
	require.NoError(t, err)
	err = decodeBindingError(m)
	var responseErr *ResponseError
	require.ErrorAs(t, err, &responseErr)
	require.Equal(t, 420, responseErr.Code)
	require.Equal(t, "Unknown", responseErr.Reason)
}

func TestDecodeBindingErrorReasonPhrase(t *testing.T) {
	id := transactionID{1, 2, 3}
	tests := []struct {
		name          string
		reason        []byte
		wantMalformed bool
		wantReason    string
	}{
		{name: "invalid UTF-8", reason: []byte{0xff}, wantMalformed: true},
		{name: "128 ASCII characters", reason: []byte(strings.Repeat("a", 128)), wantMalformed: true},
		{name: "127 multibyte characters", reason: []byte(strings.Repeat("\u754c", 127)), wantReason: strings.Repeat("\u754c", 127)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := append([]byte{0, 0, 4, 20}, tt.reason...)
			m, err := parseMessage(makeTestMessage(bindingError, id, testAttribute{typ: attrErrorCode, value: value}))
			require.NoError(t, err)
			err = decodeBindingError(m)
			if tt.wantMalformed {
				require.ErrorIs(t, err, ErrMalformedResponse)
				var responseErr *ResponseError
				require.False(t, errors.As(err, &responseErr))
				return
			}

			var responseErr *ResponseError
			require.ErrorAs(t, err, &responseErr)
			require.Equal(t, 420, responseErr.Code)
			require.Equal(t, tt.wantReason, responseErr.Reason)
		})
	}
}

func TestDecodeBindingErrorRejectsMalformedErrorCode(t *testing.T) {
	id := transactionID{1, 2, 3}
	tests := []struct {
		name       string
		attributes []testAttribute
	}{
		{name: "missing"},
		{name: "short", attributes: []testAttribute{{typ: attrErrorCode, value: []byte{0, 0, 4}}}},
		{name: "class", attributes: []testAttribute{{typ: attrErrorCode, value: []byte{0, 0, 2, 0}}}},
		{name: "number", attributes: []testAttribute{{typ: attrErrorCode, value: []byte{0, 0, 4, 100}}}},
		{name: "reason too long", attributes: []testAttribute{{
			typ:   attrErrorCode,
			value: append([]byte{0, 0, 4, 0}, make([]byte, maxErrorReasonSize+1)...),
		}}},
		{name: "invalid first duplicate", attributes: []testAttribute{
			{typ: attrErrorCode, value: []byte{0, 0, 2, 0}},
			{typ: attrErrorCode, value: []byte{0, 0, 4, 0}},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := parseMessage(makeTestMessage(bindingError, id, tt.attributes...))
			require.NoError(t, err)
			err = decodeBindingError(m)
			require.ErrorIs(t, err, ErrMalformedResponse)
			var responseErr *ResponseError
			require.False(t, errors.As(err, &responseErr))
		})
	}
}
