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
	"encoding"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	messageHeaderSize   = 20
	transactionIDSize   = 12
	attributeHeaderSize = 4
	attributeAlignment  = 4
	magicCookie         = 0x2112a442

	bindingRequest = 0x0001
	bindingSuccess = 0x0101
	bindingError   = 0x0111

	attrMappedAddress    = 0x0001
	attrChangedAddress   = 0x0005
	attrErrorCode        = 0x0009
	attrXORMappedAddress = 0x0020
	attrOtherAddress     = 0x802c
)

type transactionID [transactionIDSize]byte

type attributeValue struct {
	typ   uint16
	value []byte
}

// Message is an ownership-safe binary codec for one STUN message.
//
// The zero value is ready for UnmarshalBinary. A successful unmarshal replaces
// the previous contents and copies data; a failed unmarshal leaves the Message
// unchanged. MarshalBinary returns a new byte slice on every call. Message
// preserves attributes it does not interpret, including their padding, but it
// deliberately exposes no general-purpose attribute setters.
//
// A Message may be reused serially. It must not be unmarshaled concurrently
// with any other method call.
type Message struct {
	typ           uint16
	transactionID transactionID
	attributes    []attributeValue
	wire          []byte
}

var (
	_ encoding.BinaryMarshaler   = Message{}
	_ encoding.BinaryUnmarshaler = (*Message)(nil)
)

// MarshalBinary returns an independent copy of the encoded message.
func (m Message) MarshalBinary() ([]byte, error) {
	if len(m.wire) == 0 {
		return nil, fmt.Errorf("cannot marshal an uninitialized STUN Message")
	}
	return append([]byte(nil), m.wire...), nil
}

// UnmarshalBinary strictly decodes one complete STUN datagram.
//
// The input is copied. Malformed framing wraps ErrMalformedResponse. Supported
// Binding semantics are interpreted later by BindingTransaction.
func (m *Message) UnmarshalBinary(data []byte) error {
	if m == nil {
		return fmt.Errorf("cannot unmarshal into a nil STUN Message")
	}

	decoded, err := parseMessageCopy(data)
	if err != nil {
		return err
	}
	*m = decoded
	return nil
}

// TransactionID returns the message's 96-bit transaction identifier.
func (m Message) TransactionID() [12]byte {
	return m.transactionID
}

// IsBindingRequest reports whether m is a STUN Binding request.
func (m Message) IsBindingRequest() bool {
	return len(m.wire) != 0 && m.typ == bindingRequest
}

// IsBindingResponse reports whether m is a success or error response to a
// STUN Binding request. It does not associate the response with a transaction.
func (m Message) IsBindingResponse() bool {
	return len(m.wire) != 0 && (m.typ == bindingSuccess || m.typ == bindingError)
}

func newTransactionID(r io.Reader) (transactionID, error) {
	var id transactionID
	_, err := io.ReadFull(r, id[:])
	return id, err
}

func newBindingRequestMessage(id transactionID) Message {
	request := buildBindingRequest(id)
	return Message{
		typ:           bindingRequest,
		transactionID: id,
		wire:          append([]byte(nil), request[:]...),
	}
}

func buildBindingRequest(id transactionID) [messageHeaderSize]byte {
	var request [messageHeaderSize]byte
	binary.BigEndian.PutUint16(request[0:2], bindingRequest)
	binary.BigEndian.PutUint16(request[2:4], 0)
	binary.BigEndian.PutUint32(request[4:8], magicCookie)
	copy(request[8:20], id[:])
	return request
}

func isCorrelatedResponse(data []byte, id transactionID) bool {
	if len(data) < messageHeaderSize {
		return false
	}
	typ := binary.BigEndian.Uint16(data[0:2])
	if typ != bindingSuccess && typ != bindingError {
		return false
	}
	if binary.BigEndian.Uint32(data[4:8]) != magicCookie {
		return false
	}
	return transactionID(data[8:20]) == id
}

func parseMessage(data []byte) (Message, error) {
	return parseMessageCopy(data)
}

func parseMessageCopy(data []byte) (Message, error) {
	var m Message
	if len(data) < messageHeaderSize {
		return m, malformedResponsef("packet is %d bytes, want at least %d", len(data), messageHeaderSize)
	}

	wire := append([]byte(nil), data...)
	m.typ = binary.BigEndian.Uint16(wire[0:2])
	if m.typ&0xc000 != 0 {
		return Message{}, malformedResponsef("message type 0x%04x has nonzero leading bits", m.typ)
	}
	if binary.BigEndian.Uint32(wire[4:8]) != magicCookie {
		return Message{}, malformedResponsef("invalid magic cookie")
	}
	copy(m.transactionID[:], wire[8:20])

	declaredLength := int(binary.BigEndian.Uint16(wire[2:4]))
	if declaredLength%attributeAlignment != 0 {
		return Message{}, malformedResponsef("message length %d is not a multiple of %d", declaredLength, attributeAlignment)
	}
	expectedLength := messageHeaderSize + declaredLength
	if len(wire) != expectedLength {
		return Message{}, malformedResponsef("packet is %d bytes, header declares %d", len(wire), expectedLength)
	}

	for offset := messageHeaderSize; offset < len(wire); {
		remaining := len(wire) - offset
		if remaining < attributeHeaderSize {
			return Message{}, malformedResponsef("attribute header is truncated at offset %d", offset)
		}
		attributeType := binary.BigEndian.Uint16(wire[offset : offset+2])
		valueLength := int(binary.BigEndian.Uint16(wire[offset+2 : offset+4]))
		paddedLength := (valueLength + attributeAlignment - 1) &^ (attributeAlignment - 1)
		if remaining-attributeHeaderSize < paddedLength {
			return Message{}, malformedResponsef("attribute 0x%04x value or padding is truncated", attributeType)
		}
		valueStart := offset + attributeHeaderSize
		m.attributes = append(m.attributes, attributeValue{
			typ:   attributeType,
			value: wire[valueStart : valueStart+valueLength],
		})

		offset = valueStart + paddedLength
	}
	m.wire = wire
	return m, nil
}

func (m Message) firstAttribute(typ uint16) ([]byte, bool) {
	for _, attribute := range m.attributes {
		if attribute.typ == typ {
			return attribute.value, true
		}
	}
	return nil, false
}
