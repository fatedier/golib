package stun

import (
	"bytes"
	"net"
	"testing"
)

func FuzzParseMessageNoPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(makeTestMessage(bindingSuccess, transactionID{}))
	f.Add(makeTestMessage(bindingError, transactionID{}, testAttribute{
		typ:   attrErrorCode,
		value: []byte{0, 0, 4, 0},
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		var m Message
		err := m.UnmarshalBinary(data)
		if err != nil {
			return
		}
		encoded, err := m.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseMessage(encoded); err != nil {
			t.Fatalf("MarshalBinary produced an invalid message: %v", err)
		}
		switch m.typ {
		case bindingSuccess:
			_, _ = decodeBindingSuccess(m)
		case bindingError:
			_ = decodeBindingError(m)
		}
	})
}

func FuzzBindingTransactionProcessNoPanic(f *testing.F) {
	id := transactionID{1, 2, 3}
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}
	transaction, err := newBindingTransaction(server, bytes.NewReader(id[:]))
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(nil))
	f.Add(makeTestMessage(bindingSuccess, id))
	f.Add(makeTestMessage(bindingError, id, testAttribute{
		typ:   attrErrorCode,
		value: []byte{0, 0, 4, 0},
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, matched, err := transaction.Process(data, server)
		if !matched && err != nil {
			t.Fatalf("unmatched datagram returned an error: %v", err)
		}
	})
}
