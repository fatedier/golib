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

package stun

import (
	"encoding/binary"
	"fmt"
	"net"
	"unicode/utf8"
)

const (
	addressFamilyIPv4  = 0x01
	addressFamilyIPv6  = 0x02
	maxErrorReasonSize = 763
)

func decodeBindingSuccess(m Message) (BindingResponse, error) {
	var response BindingResponse
	var err error

	if value, ok := m.firstAttribute(attrXORMappedAddress); ok {
		response.MappedAddr, err = decodeAddress(value, m.transactionID, true)
	} else if value, ok := m.firstAttribute(attrMappedAddress); ok {
		response.MappedAddr, err = decodeAddress(value, m.transactionID, false)
	}
	if err != nil {
		return BindingResponse{}, err
	}

	if value, ok := m.firstAttribute(attrOtherAddress); ok {
		response.OtherAddr, err = decodeAddress(value, m.transactionID, false)
	} else if value, ok := m.firstAttribute(attrChangedAddress); ok {
		response.OtherAddr, err = decodeAddress(value, m.transactionID, false)
	}
	if err != nil {
		return BindingResponse{}, err
	}
	return response, nil
}

func decodeAddress(value []byte, id transactionID, xor bool) (*net.UDPAddr, error) {
	if len(value) < 4 {
		return nil, malformedResponsef("address attribute is %d bytes, want at least 4", len(value))
	}
	var header [4]byte
	copy(header[:], value)

	var ipLength int
	family := header[1]
	switch family {
	case addressFamilyIPv4:
		ipLength = net.IPv4len
	case addressFamilyIPv6:
		ipLength = net.IPv6len
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedAddressFamily, family)
	}
	if len(value) != 4+ipLength {
		return nil, malformedResponsef("address family 0x%02x has value length %d, want %d", family, len(value), 4+ipLength)
	}

	port := binary.BigEndian.Uint16(header[2:4])
	addressBytes := value[4 : 4+ipLength] //nolint:gosec // The exact value length is checked above.
	ip := append(net.IP(nil), addressBytes...)
	if xor {
		port ^= uint16(magicCookie >> 16)
		var mask [net.IPv6len]byte
		binary.BigEndian.PutUint32(mask[0:4], magicCookie)
		copy(mask[4:], id[:])
		for i := range ip {
			ip[i] ^= mask[i]
		}
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

func decodeBindingError(m Message) error {
	value, ok := m.firstAttribute(attrErrorCode)
	if !ok {
		return malformedResponsef("Binding error response has no ERROR-CODE attribute")
	}
	if len(value) < 4 {
		return malformedResponsef("ERROR-CODE attribute is %d bytes, want at least 4", len(value))
	}
	if len(value)-4 > maxErrorReasonSize {
		return malformedResponsef("ERROR-CODE reason is %d bytes, want at most %d", len(value)-4, maxErrorReasonSize)
	}
	reason := value[4:]
	if !utf8.Valid(reason) {
		return malformedResponsef("ERROR-CODE reason is not valid UTF-8")
	}
	if runeCount := utf8.RuneCount(reason); runeCount >= 128 {
		return malformedResponsef("ERROR-CODE reason is %d characters, want fewer than 128", runeCount)
	}
	class := int(value[2] & 0x07)
	number := int(value[3])
	if class < 3 || class > 6 || number > 99 {
		return malformedResponsef("invalid ERROR-CODE class %d number %d", class, number)
	}
	return &ResponseError{
		Code:   class*100 + number,
		Reason: string(reason),
	}
}
