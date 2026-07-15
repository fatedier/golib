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
	"crypto/rand"
	"encoding"
	"fmt"
	"io"
	"net"
	"strconv"
)

const maxUDPPacketSize = 64 * 1024

// BindingResponse contains addresses returned by a successful Binding
// transaction. Either field may be nil when the server omitted that address.
// The addresses do not alias the response datagram.
type BindingResponse struct {
	// MappedAddr is the server-observed address of the client.
	MappedAddr *net.UDPAddr
	// OtherAddr is the alternate server address advertised by the server.
	OtherAddr *net.UDPAddr
}

// Client performs synchronous STUN transactions over a caller-owned UDP
// connection.
//
// A Client borrows its connection: it never closes it, changes its deadlines,
// retries a request, or starts background goroutines. A Client may be reused
// sequentially. The caller must ensure that no other goroutine reads from the
// same connection while Do is running, including through another Client.
type Client struct {
	conn *net.UDPConn
}

// NewClient returns a Client that uses conn for synchronous STUN transactions.
// The caller retains ownership of conn.
func NewClient(conn *net.UDPConn) (*Client, error) {
	if conn == nil {
		return nil, fmt.Errorf("STUN Client requires a non-nil UDP connection")
	}
	return &Client{conn: conn}, nil
}

// BindingTransaction associates one Binding request with its expected server.
//
// It is immutable after construction. MarshalBinary may be called repeatedly
// and always returns a new request buffer. Process does not mark the
// transaction complete, so callers own retransmission, timeout, and lifecycle
// policy. Its methods are safe for concurrent use.
type BindingTransaction struct {
	request Message
	server  net.UDPAddr
}

var _ encoding.BinaryMarshaler = (*BindingTransaction)(nil)

// NewBindingTransaction creates a Binding transaction for server.
//
// The server address, including its IP bytes, is copied. Responses from any
// other source are considered unrelated to the transaction.
func NewBindingTransaction(server *net.UDPAddr) (*BindingTransaction, error) {
	return newBindingTransaction(server, rand.Reader)
}

func newBindingTransaction(server *net.UDPAddr, entropy io.Reader) (*BindingTransaction, error) {
	if err := validateServer(server); err != nil {
		return nil, err
	}
	id, err := newTransactionID(entropy)
	if err != nil {
		return nil, err
	}
	return &BindingTransaction{
		request: newBindingRequestMessage(id),
		server:  cloneUDPAddr(server),
	}, nil
}

// MarshalBinary returns a new copy of the Binding request datagram.
func (t *BindingTransaction) MarshalBinary() ([]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("cannot marshal a nil STUN BindingTransaction")
	}
	return t.request.MarshalBinary()
}

// TransactionID returns the transaction's 96-bit identifier.
func (t *BindingTransaction) TransactionID() [12]byte {
	if t == nil {
		return [12]byte{}
	}
	return t.request.TransactionID()
}

// Process associates and decodes a caller-received datagram.
//
// matched is false with a nil error when source, message type, magic cookie,
// or transaction ID does not identify this transaction. Once those fields
// match, matched is true: malformed framing or malformed supported attributes
// return an error wrapping ErrMalformedResponse, an unsupported address family
// wraps ErrUnsupportedAddressFamily, and a STUN Binding error returns a
// *ResponseError. The packet and source address are never retained.
func (t *BindingTransaction) Process(
	packet []byte,
	source *net.UDPAddr,
) (response BindingResponse, matched bool, err error) {
	if t == nil {
		return BindingResponse{}, false, fmt.Errorf("cannot process a response with a nil STUN BindingTransaction")
	}
	if !sameUDPAddress(source, &t.server) || !isCorrelatedResponse(packet, t.request.transactionID) {
		return BindingResponse{}, false, nil
	}

	var message Message
	if err := message.UnmarshalBinary(packet); err != nil {
		return BindingResponse{}, true, err
	}
	switch message.typ {
	case bindingSuccess:
		response, err := decodeBindingSuccess(message)
		return response, true, err
	case bindingError:
		return BindingResponse{}, true, decodeBindingError(message)
	default:
		panic("correlated STUN response has unexpected type")
	}
}

// Do performs one synchronous STUN Binding transaction.
//
// The transaction's server may be used with an unconnected connection or with
// a connection connected to that server. Do rejects a different connected
// peer before sending. It sends exactly one copy returned by t.MarshalBinary,
// then processes each received datagram with t.Process until one matches.
// Unrelated datagrams are discarded. Network errors are returned unchanged.
//
// Do does not set or restore connection deadlines, retry, close the connection,
// or mark t complete. The caller must arrange any deadline and serialize all
// reads from the connection until Do returns.
func (c *Client) Do(t *BindingTransaction) (BindingResponse, error) {
	if c == nil {
		return BindingResponse{}, fmt.Errorf("cannot use a nil STUN Client")
	}
	if c.conn == nil {
		return BindingResponse{}, fmt.Errorf("STUN Client has no UDP connection")
	}
	if t == nil {
		return BindingResponse{}, fmt.Errorf("STUN Client.Do requires a non-nil BindingTransaction")
	}

	connectedPeer, connected := c.conn.RemoteAddr().(*net.UDPAddr)
	if connected && !sameUDPAddress(connectedPeer, &t.server) {
		return BindingResponse{}, fmt.Errorf(
			"STUN Binding server %s does not match connected UDP peer %s",
			&t.server,
			connectedPeer,
		)
	}

	request, err := t.MarshalBinary()
	if err != nil {
		return BindingResponse{}, err
	}
	var n int
	if connected {
		n, err = c.conn.Write(request)
	} else {
		n, err = c.conn.WriteToUDP(request, &t.server)
	}
	if err != nil {
		return BindingResponse{}, err
	}
	if n != len(request) {
		return BindingResponse{}, io.ErrShortWrite
	}

	buffer := make([]byte, maxUDPPacketSize)
	for {
		n, source, err := c.conn.ReadFromUDP(buffer)
		if err != nil {
			return BindingResponse{}, err
		}
		response, matched, err := t.Process(buffer[:n], source)
		if !matched {
			continue
		}
		return response, err
	}
}

func validateServer(server *net.UDPAddr) error {
	if server == nil {
		return fmt.Errorf("STUN Binding requires a non-nil server address")
	}
	if server.IP.To4() == nil && server.IP.To16() == nil {
		return fmt.Errorf("%w: server address %q", ErrUnsupportedAddressFamily, server.IP)
	}
	return nil
}

func cloneUDPAddr(address *net.UDPAddr) net.UDPAddr {
	return net.UDPAddr{
		IP:   append(net.IP(nil), address.IP...),
		Port: address.Port,
		Zone: address.Zone,
	}
}

func sameUDPAddress(a, b *net.UDPAddr) bool {
	if a == nil || b == nil || a.Port != b.Port || !a.IP.Equal(b.IP) {
		return false
	}
	if !ipv6NeedsZone(a.IP) || a.Zone == b.Zone {
		return true
	}
	aIndex, aOK := zoneInterfaceIndex(a.Zone)
	bIndex, bOK := zoneInterfaceIndex(b.Zone)
	return aOK && bOK && aIndex == bIndex
}

func ipv6NeedsZone(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	ip = ip.To16()
	if ip == nil {
		return false
	}
	if ip.IsLinkLocalUnicast() {
		return true
	}
	if ip[0] != 0xff {
		return false
	}
	// IPv6 multicast encodes its scope in the low nibble of byte 1.
	// Scope e is global; 0 and f are reserved.
	scope := ip[1] & 0x0f
	return scope > 0 && scope < 0x0e
}

func zoneInterfaceIndex(zone string) (int, bool) {
	if zone == "" {
		return 0, true
	}
	if iface, err := net.InterfaceByName(zone); err == nil {
		return iface.Index, true
	}
	index, err := strconv.ParseUint(zone, 10, 0)
	if err != nil || index > uint64(^uint(0)>>1) {
		return 0, false
	}
	if index == 0 {
		return 0, true
	}
	iface, err := net.InterfaceByIndex(int(index))
	if err != nil {
		return 0, false
	}
	return iface.Index, true
}
