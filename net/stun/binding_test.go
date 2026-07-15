package stun

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testSocketTimeout = 2 * time.Second

func listenUDP4(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func serveOneBinding(
	server *net.UDPConn,
	response func(transactionID, *net.UDPAddr) ([]byte, error),
) <-chan error {
	done := make(chan error, 1)
	go func() {
		if err := server.SetDeadline(time.Now().Add(testSocketTimeout)); err != nil {
			done <- err
			return
		}
		buffer := make([]byte, 1024)
		n, clientAddr, err := server.ReadFromUDP(buffer)
		if err != nil {
			done <- err
			return
		}
		if n != messageHeaderSize {
			done <- fmt.Errorf("request is %d bytes, want %d", n, messageHeaderSize)
			return
		}
		if binary.BigEndian.Uint16(buffer[0:2]) != bindingRequest {
			done <- fmt.Errorf("request has type 0x%04x", binary.BigEndian.Uint16(buffer[0:2]))
			return
		}
		var id transactionID
		copy(id[:], buffer[8:20])
		packet, err := response(id, clientAddr)
		if err == nil {
			_, err = server.WriteToUDP(packet, clientAddr)
		}
		done <- err
	}()
	return done
}

func waitServer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(testSocketTimeout + time.Second):
		t.Fatal("timed out waiting for local STUN server")
	}
}

func TestClientDropsUnrelatedDatagrams(t *testing.T) {
	server := listenUDP4(t)
	foreign := listenUDP4(t)
	conn := listenUDP4(t)
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	done := serveOneBinding(server, func(id transactionID, clientAddr *net.UDPAddr) ([]byte, error) {
		mapped := testAttribute{
			typ:   attrXORMappedAddress,
			value: xorAddressValue(net.ParseIP("198.51.100.42"), 45678, id),
		}
		valid := makeTestMessage(bindingSuccess, id, mapped)

		if _, err := foreign.WriteToUDP(valid, clientAddr); err != nil {
			return nil, err
		}
		if _, err := server.WriteToUDP([]byte{0, 1, 2}, clientAddr); err != nil {
			return nil, err
		}
		wrongCookie := append([]byte(nil), valid...)
		wrongCookie[4] ^= 1
		if _, err := server.WriteToUDP(wrongCookie, clientAddr); err != nil {
			return nil, err
		}
		wrongID := append([]byte(nil), valid...)
		wrongID[8] ^= 1
		if _, err := server.WriteToUDP(wrongID, clientAddr); err != nil {
			return nil, err
		}
		wrongType := append([]byte(nil), valid...)
		binary.BigEndian.PutUint16(wrongType[0:2], bindingRequest)
		if _, err := server.WriteToUDP(wrongType, clientAddr); err != nil {
			return nil, err
		}
		wrongMethod := append([]byte(nil), valid...)
		binary.BigEndian.PutUint16(wrongMethod[0:2], 0x0103)
		if _, err := server.WriteToUDP(wrongMethod, clientAddr); err != nil {
			return nil, err
		}
		return valid, nil
	})

	client, err := NewClient(conn)
	require.NoError(t, err)
	transaction, err := NewBindingTransaction(serverAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(testSocketTimeout)))
	response, err := client.Do(transaction)
	require.NoError(t, err)
	require.Equal(t, "198.51.100.42:45678", response.MappedAddr.String())
	waitServer(t, done)
}

func TestBindingTransactionRequestAndServerOwnership(t *testing.T) {
	id := transactionID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	server := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 3478}
	expectedSource := cloneUDPAddr(server)
	transaction, err := newBindingTransaction(server, bytes.NewReader(id[:]))
	require.NoError(t, err)

	var marshaler encoding.BinaryMarshaler = transaction
	first, err := marshaler.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, [12]byte(id), transaction.TransactionID())
	require.Equal(t, "000100002112a442000102030405060708090a0b", fmt.Sprintf("%x", first))
	first[0] ^= 0xff
	second, err := transaction.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, "000100002112a442000102030405060708090a0b", fmt.Sprintf("%x", second))

	server.IP[0] ^= 0xff
	server.Port++
	packet := makeTestMessage(bindingSuccess, id, testAttribute{
		typ:   attrMappedAddress,
		value: plainAddressValue(net.ParseIP("198.51.100.20"), 40000),
	})
	response, matched, err := transaction.Process(packet, &expectedSource)
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "198.51.100.20:40000", response.MappedAddr.String())

	for i := range packet {
		packet[i] ^= 0xff
	}
	require.Equal(t, "198.51.100.20:40000", response.MappedAddr.String())
}

func TestBindingTransactionConcurrentMethods(t *testing.T) {
	id := transactionID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	server := &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 3478}
	transaction, err := newBindingTransaction(server, bytes.NewReader(id[:]))
	require.NoError(t, err)
	packet := makeTestMessage(bindingSuccess, id, testAttribute{
		typ:   attrMappedAddress,
		value: plainAddressValue(net.ParseIP("198.51.100.20"), 40000),
	})
	wantRequest := buildBindingRequest(id)

	const callsPerMethod = 32
	start := make(chan struct{})
	results := make(chan error, callsPerMethod*3)
	var workers sync.WaitGroup
	workers.Add(callsPerMethod * 3)
	for range callsPerMethod {
		go func() {
			defer workers.Done()
			<-start
			request, err := transaction.MarshalBinary()
			if err == nil && !bytes.Equal(request, wantRequest[:]) {
				err = fmt.Errorf("MarshalBinary returned %x, want %x", request, wantRequest)
			}
			results <- err
		}()
		go func() {
			defer workers.Done()
			<-start
			if got := transaction.TransactionID(); got != [12]byte(id) {
				results <- fmt.Errorf("TransactionID returned %x, want %x", got, id)
				return
			}
			results <- nil
		}()
		go func() {
			defer workers.Done()
			<-start
			response, matched, err := transaction.Process(packet, server)
			if err == nil && !matched {
				err = errors.New("Process did not match the response")
			}
			if err == nil && (response.MappedAddr == nil || response.MappedAddr.String() != "198.51.100.20:40000") {
				err = fmt.Errorf("Process returned mapped address %v", response.MappedAddr)
			}
			results <- err
		}()
	}

	close(start)
	workers.Wait()
	close(results)
	resultCount := 0
	for err := range results {
		require.NoError(t, err)
		resultCount++
	}
	require.Equal(t, callsPerMethod*3, resultCount)
}

func TestBindingTransactionClassifiesDatagrams(t *testing.T) {
	id := transactionID{1, 2, 3}
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}
	transaction, err := newBindingTransaction(server, bytes.NewReader(id[:]))
	require.NoError(t, err)
	valid := makeTestMessage(bindingSuccess, id, testAttribute{
		typ:   attrXORMappedAddress,
		value: xorAddressValue(net.ParseIP("198.51.100.30"), 41000, id),
	})

	tests := []struct {
		name   string
		packet []byte
		source *net.UDPAddr
	}{
		{name: "nil source", packet: valid},
		{name: "source IP", packet: valid, source: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: server.Port}},
		{name: "source port", packet: valid, source: &net.UDPAddr{IP: server.IP, Port: server.Port + 1}},
		{name: "short", packet: valid[:messageHeaderSize-1], source: server},
		{name: "request type", packet: func() []byte {
			packet := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(packet[0:2], bindingRequest)
			return packet
		}(), source: server},
		{name: "cookie", packet: func() []byte {
			packet := append([]byte(nil), valid...)
			packet[4] ^= 1
			return packet
		}(), source: server},
		{name: "transaction ID", packet: func() []byte {
			packet := append([]byte(nil), valid...)
			packet[8] ^= 1
			return packet
		}(), source: server},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, matched, err := transaction.Process(tt.packet, tt.source)
			require.NoError(t, err)
			require.False(t, matched)
			require.Equal(t, BindingResponse{}, response)
		})
	}

	response, matched, err := transaction.Process(valid, &net.UDPAddr{
		IP:   server.IP,
		Port: server.Port,
		Zone: "ignored-for-ipv4",
	})
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "198.51.100.30:41000", response.MappedAddr.String())

	response, matched, err = transaction.Process(valid, server)
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "198.51.100.30:41000", response.MappedAddr.String())
}

func TestBindingTransactionProcessMatchesScopeZeroZone(t *testing.T) {
	if iface, err := net.InterfaceByName("0"); err == nil {
		t.Skipf("interface %q has index %d and takes precedence over numeric zone parsing", iface.Name, iface.Index)
	}

	id := transactionID{1, 2, 3}
	packet := makeTestMessage(bindingSuccess, id)
	tests := []struct {
		name       string
		ip         net.IP
		serverZone string
		sourceZone string
	}{
		{name: "scoped unicast empty to zero", ip: net.ParseIP("fe80::1"), sourceZone: "0"},
		{name: "scoped unicast zero to empty", ip: net.ParseIP("fe80::1"), serverZone: "0"},
		{name: "scoped multicast empty to zero", ip: net.ParseIP("ff02::1"), sourceZone: "0"},
		{name: "scoped multicast zero to empty", ip: net.ParseIP("ff02::1"), serverZone: "0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &net.UDPAddr{IP: tt.ip, Port: 3478, Zone: tt.serverZone}
			transaction, err := newBindingTransaction(server, bytes.NewReader(id[:]))
			require.NoError(t, err)
			response, matched, err := transaction.Process(packet, &net.UDPAddr{
				IP:   tt.ip,
				Port: server.Port,
				Zone: tt.sourceZone,
			})
			require.NoError(t, err)
			require.True(t, matched)
			require.Equal(t, BindingResponse{}, response)
		})
	}
}

func TestNewBindingTransactionValidatesServer(t *testing.T) {
	_, err := NewBindingTransaction(nil)
	require.Error(t, err)

	_, err = NewBindingTransaction(&net.UDPAddr{IP: net.IP{1, 2, 3}, Port: 3478})
	require.ErrorIs(t, err, ErrUnsupportedAddressFamily)
}

func TestBindingTransactionRelatedMalformedAndErrorResponses(t *testing.T) {
	id := transactionID{1, 2, 3}
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}
	transaction, err := newBindingTransaction(server, bytes.NewReader(id[:]))
	require.NoError(t, err)

	malformed := append(makeTestMessage(bindingSuccess, id), 0, 0, 0, 0)
	_, matched, err := transaction.Process(malformed, server)
	require.True(t, matched)
	require.ErrorIs(t, err, ErrMalformedResponse)

	_, matched, err = transaction.Process(malformed, &net.UDPAddr{IP: server.IP, Port: server.Port + 1})
	require.False(t, matched)
	require.NoError(t, err)

	errorPacket := makeTestMessage(bindingError, id, testAttribute{
		typ:   attrErrorCode,
		value: []byte{0, 0, 4, 20, 'U', 'n', 'k', 'n', 'o', 'w', 'n'},
	})
	_, matched, err = transaction.Process(errorPacket, server)
	require.True(t, matched)
	var responseErr *ResponseError
	require.ErrorAs(t, err, &responseErr)
	require.Equal(t, 420, responseErr.Code)
}

func TestCallerManagedIOAndClientUseSameSemantics(t *testing.T) {
	server := listenUDP4(t)
	conn := listenUDP4(t)
	serverAddr := server.LocalAddr().(*net.UDPAddr)
	responsePacket := func(id transactionID, _ *net.UDPAddr) ([]byte, error) {
		return makeTestMessage(bindingSuccess, id,
			testAttribute{
				typ:   attrMappedAddress,
				value: plainAddressValue(net.ParseIP("192.0.2.1"), 1000),
			},
			testAttribute{
				typ:   attrXORMappedAddress,
				value: xorAddressValue(net.ParseIP("198.51.100.40"), 42000, id),
			},
		), nil
	}

	lowLevelDone := serveOneBinding(server, responsePacket)
	transaction, err := NewBindingTransaction(serverAddr)
	require.NoError(t, err)
	request, err := transaction.MarshalBinary()
	require.NoError(t, err)
	_, err = conn.WriteToUDP(request, serverAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(testSocketTimeout)))
	buffer := make([]byte, 1024)
	n, source, err := conn.ReadFromUDP(buffer)
	require.NoError(t, err)
	lowLevelResponse, matched, err := transaction.Process(buffer[:n], source)
	require.NoError(t, err)
	require.True(t, matched)
	waitServer(t, lowLevelDone)

	highLevelDone := serveOneBinding(server, responsePacket)
	client, err := NewClient(conn)
	require.NoError(t, err)
	highLevelTransaction, err := NewBindingTransaction(serverAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(testSocketTimeout)))
	highLevelResponse, err := client.Do(highLevelTransaction)
	require.NoError(t, err)
	waitServer(t, highLevelDone)

	require.Equal(t, lowLevelResponse.MappedAddr.String(), highLevelResponse.MappedAddr.String())
	require.Equal(t, "198.51.100.40:42000", highLevelResponse.MappedAddr.String())
}

func TestClientDoAndTransactionProcessHaveEquivalentSemantics(t *testing.T) {
	tests := []struct {
		name   string
		packet func(transactionID) []byte
	}{
		{
			name: "success",
			packet: func(id transactionID) []byte {
				return makeTestMessage(bindingSuccess, id, testAttribute{
					typ:   attrXORMappedAddress,
					value: xorAddressValue(net.ParseIP("198.51.100.44"), 43000, id),
				})
			},
		},
		{
			name: "Binding error",
			packet: func(id transactionID) []byte {
				return makeTestMessage(bindingError, id, testAttribute{
					typ:   attrErrorCode,
					value: []byte{0, 0, 4, 20, 'U', 'n', 'k', 'n', 'o', 'w', 'n'},
				})
			},
		},
		{
			name: "correlated malformed response",
			packet: func(id transactionID) []byte {
				return append(makeTestMessage(bindingSuccess, id), 0, 0, 0, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := listenUDP4(t)
			serverAddr := server.LocalAddr().(*net.UDPAddr)

			directTransaction, err := NewBindingTransaction(serverAddr)
			require.NoError(t, err)
			directResponse, matched, directErr := directTransaction.Process(
				tt.packet(transactionID(directTransaction.TransactionID())),
				serverAddr,
			)
			require.True(t, matched)

			done := serveOneBinding(server, func(id transactionID, _ *net.UDPAddr) ([]byte, error) {
				return tt.packet(id), nil
			})
			conn := listenUDP4(t)
			client, err := NewClient(conn)
			require.NoError(t, err)
			clientTransaction, err := NewBindingTransaction(serverAddr)
			require.NoError(t, err)
			require.NoError(t, conn.SetDeadline(time.Now().Add(testSocketTimeout)))
			clientResponse, clientErr := client.Do(clientTransaction)
			waitServer(t, done)

			require.Equal(t, directResponse, clientResponse)
			require.Equal(t, fmt.Sprintf("%T", directErr), fmt.Sprintf("%T", clientErr))
			if directErr == nil {
				require.NoError(t, clientErr)
				return
			}
			require.EqualError(t, clientErr, directErr.Error())
		})
	}
}

func TestClientSupportsConnectedMatchingPeer(t *testing.T) {
	server := listenUDP4(t)
	serverAddr := server.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp4", nil, serverAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	done := serveOneBinding(server, func(id transactionID, _ *net.UDPAddr) ([]byte, error) {
		return makeTestMessage(bindingSuccess, id, testAttribute{
			typ:   attrXORMappedAddress,
			value: xorAddressValue(net.ParseIP("198.51.100.43"), 45679, id),
		}), nil
	})

	client, err := NewClient(conn)
	require.NoError(t, err)
	serverWithZone := cloneUDPAddr(serverAddr)
	serverWithZone.Zone = "ignored-for-ipv4"
	transaction, err := NewBindingTransaction(&serverWithZone)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(testSocketTimeout)))
	response, err := client.Do(transaction)
	require.NoError(t, err)
	require.Equal(t, "198.51.100.43:45679", response.MappedAddr.String())
	waitServer(t, done)
}

func TestSameUDPAddressZones(t *testing.T) {
	tests := []struct {
		name string
		a    *net.UDPAddr
		b    *net.UDPAddr
		want bool
	}{
		{
			name: "IPv4 ignores zone",
			a:    &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 3478, Zone: "first"},
			b:    &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3478, Zone: "second"},
			want: true,
		},
		{
			name: "global IPv6 ignores zone",
			a:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 3478, Zone: "first"},
			b:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 3478, Zone: "second"},
			want: true,
		},
		{
			name: "global IPv6 multicast ignores zone",
			a:    &net.UDPAddr{IP: net.ParseIP("ff0e::1"), Port: 3478, Zone: "first"},
			b:    &net.UDPAddr{IP: net.ParseIP("ff0e::1"), Port: 3478, Zone: "second"},
			want: true,
		},
		{
			name: "scoped IPv6 same zone",
			a:    &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 3478, Zone: "same"},
			b:    &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 3478, Zone: "same"},
			want: true,
		},
		{
			name: "scoped IPv6 different zone",
			a:    &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 3478},
			b:    &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 3478, Zone: "\x00"},
			want: false,
		},
		{
			name: "scoped IPv6 multicast different zone",
			a:    &net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: 3478},
			b:    &net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: 3478, Zone: "\x00"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, sameUDPAddress(tt.a, tt.b))
			require.Equal(t, tt.want, sameUDPAddress(tt.b, tt.a))
		})
	}
}

func TestSameUDPAddressIPv4Representations(t *testing.T) {
	ipv4 := net.ParseIP("192.0.2.1").To4()
	mapped := net.ParseIP("192.0.2.1")
	require.Len(t, ipv4, net.IPv4len)
	require.Len(t, mapped, net.IPv6len)

	a := &net.UDPAddr{IP: ipv4, Port: 3478, Zone: "first"}
	b := &net.UDPAddr{IP: mapped, Port: 3478, Zone: "second"}
	require.True(t, sameUDPAddress(a, b))
	require.True(t, sameUDPAddress(b, a))
}

func TestSameUDPAddressScopeZeroZones(t *testing.T) {
	if iface, err := net.InterfaceByName("0"); err == nil {
		t.Skipf("interface %q has index %d and takes precedence over numeric zone parsing", iface.Name, iface.Index)
	}

	for _, tt := range []struct {
		name string
		ip   net.IP
	}{
		{name: "scoped unicast", ip: net.ParseIP("fe80::1")},
		{name: "scoped multicast", ip: net.ParseIP("ff02::1")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			emptyZone := &net.UDPAddr{IP: tt.ip, Port: 3478}
			zeroZone := &net.UDPAddr{IP: tt.ip, Port: 3478, Zone: "0"}
			require.True(t, sameUDPAddress(emptyZone, zeroZone))
			require.True(t, sameUDPAddress(zeroZone, emptyZone))
		})
	}
}

func TestSameUDPAddressMatchesInterfaceNameAndIndex(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot list network interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Name == "" || iface.Index <= 0 {
			continue
		}
		byName, nameErr := net.InterfaceByName(iface.Name)
		byIndex, indexErr := net.InterfaceByIndex(iface.Index)
		if nameErr != nil || indexErr != nil || byName.Index != byIndex.Index {
			continue
		}
		indexZone := fmt.Sprint(iface.Index)
		if numericName, err := net.InterfaceByName(indexZone); err == nil && numericName.Index != iface.Index {
			continue
		}
		addressByName := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 3478, Zone: iface.Name}
		addressByIndex := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 3478, Zone: indexZone}
		require.True(t, sameUDPAddress(addressByName, addressByIndex))
		require.True(t, sameUDPAddress(addressByIndex, addressByName))
		return
	}
	t.Skip("no network interface supports both name and index lookup")
}

func TestClientRejectsConnectedPeerMismatchWithoutSending(t *testing.T) {
	connectedServer := listenUDP4(t)
	otherServer := listenUDP4(t)
	connectedAddr := connectedServer.LocalAddr().(*net.UDPAddr)
	otherAddr := otherServer.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp4", nil, connectedAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client, err := NewClient(conn)
	require.NoError(t, err)
	transaction, err := NewBindingTransaction(otherAddr)
	require.NoError(t, err)
	_, err = client.Do(transaction)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match connected UDP peer")
	require.True(t, sameUDPAddress(conn.RemoteAddr().(*net.UDPAddr), connectedAddr))

	require.NoError(t, connectedServer.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	buffer := make([]byte, 1)
	_, _, err = connectedServer.ReadFromUDP(buffer)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())

	// Do neither sent the transaction nor closed the caller-owned connection.
	require.NoError(t, connectedServer.SetReadDeadline(time.Now().Add(testSocketTimeout)))
	_, err = conn.Write([]byte{1})
	require.NoError(t, err)
	_, _, err = connectedServer.ReadFromUDP(buffer)
	require.NoError(t, err)
}

func TestClientDeadlinePreservesNetErrorAndDoesNotRetry(t *testing.T) {
	server := listenUDP4(t)
	conn := listenUDP4(t)
	serverAddr := server.LocalAddr().(*net.UDPAddr)
	requestCount := make(chan int, 1)

	go func() {
		buffer := make([]byte, 1024)
		if err := server.SetReadDeadline(time.Now().Add(testSocketTimeout)); err != nil {
			requestCount <- 0
			return
		}
		if _, _, err := server.ReadFromUDP(buffer); err != nil {
			requestCount <- 0
			return
		}
		count := 1
		_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		for {
			_, _, err := server.ReadFromUDP(buffer)
			if err != nil {
				requestCount <- count
				return
			}
			count++
		}
	}()

	client, err := NewClient(conn)
	require.NoError(t, err)
	transaction, err := NewBindingTransaction(serverAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(250*time.Millisecond)))
	_, err = client.Do(transaction)
	require.Error(t, err)
	var netErr net.Error
	require.True(t, errors.As(err, &netErr))
	require.True(t, netErr.Timeout())

	select {
	case count := <-requestCount:
		require.Equal(t, 1, count)
	case <-time.After(testSocketTimeout):
		t.Fatal("timed out counting Binding requests")
	}

	readResult := make(chan error, 1)
	go func() {
		_, _, readErr := conn.ReadFromUDP(make([]byte, 1))
		readResult <- readErr
	}()
	select {
	case readErr := <-readResult:
		var readNetErr net.Error
		require.ErrorAs(t, readErr, &readNetErr)
		require.True(t, readNetErr.Timeout())
	case <-time.After(250 * time.Millisecond):
		_ = conn.Close()
		t.Fatal("Client.Do cleared or replaced the caller's deadline")
	}
}

func TestClientReturnsTypedResponseError(t *testing.T) {
	server := listenUDP4(t)
	conn := listenUDP4(t)
	done := serveOneBinding(server, func(id transactionID, _ *net.UDPAddr) ([]byte, error) {
		return makeTestMessage(bindingError, id, testAttribute{
			typ:   attrErrorCode,
			value: []byte{0, 0, 5, 0, 'F', 'a', 'i', 'l', 'e', 'd'},
		}), nil
	})

	client, err := NewClient(conn)
	require.NoError(t, err)
	transaction, err := NewBindingTransaction(server.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(testSocketTimeout)))
	_, err = client.Do(transaction)
	var responseErr *ResponseError
	require.ErrorAs(t, err, &responseErr)
	require.Equal(t, 500, responseErr.Code)
	require.Equal(t, "Failed", responseErr.Reason)
	waitServer(t, done)
}

func TestClientRejectsCorrelatedMalformedResponse(t *testing.T) {
	server := listenUDP4(t)
	conn := listenUDP4(t)
	done := serveOneBinding(server, func(id transactionID, _ *net.UDPAddr) ([]byte, error) {
		packet := makeTestMessage(bindingSuccess, id)
		return append(packet, 0, 0, 0, 0), nil
	})

	client, err := NewClient(conn)
	require.NoError(t, err)
	transaction, err := NewBindingTransaction(server.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(testSocketTimeout)))
	_, err = client.Do(transaction)
	require.ErrorIs(t, err, ErrMalformedResponse)
	waitServer(t, done)
}

func TestClientReusesSocketAndLocalPortForAlternateServer(t *testing.T) {
	primary := listenUDP4(t)
	alternate := listenUDP4(t)
	conn := listenUDP4(t)
	primarySource := make(chan *net.UDPAddr, 1)
	alternateSource := make(chan *net.UDPAddr, 1)

	primaryDone := serveOneBinding(primary, func(id transactionID, clientAddr *net.UDPAddr) ([]byte, error) {
		primarySource <- clientAddr
		return makeTestMessage(bindingSuccess, id,
			testAttribute{
				typ:   attrXORMappedAddress,
				value: xorAddressValue(net.ParseIP("198.51.100.1"), 41000, id),
			},
			testAttribute{
				typ:   attrOtherAddress,
				value: plainAddressValue(alternate.LocalAddr().(*net.UDPAddr).IP, alternate.LocalAddr().(*net.UDPAddr).Port),
			},
		), nil
	})
	alternateDone := serveOneBinding(alternate, func(id transactionID, clientAddr *net.UDPAddr) ([]byte, error) {
		alternateSource <- clientAddr
		return makeTestMessage(bindingSuccess, id, testAttribute{
			typ:   attrXORMappedAddress,
			value: xorAddressValue(net.ParseIP("198.51.100.1"), 41001, id),
		}), nil
	})

	client, err := NewClient(conn)
	require.NoError(t, err)
	firstTransaction, err := NewBindingTransaction(primary.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(testSocketTimeout)))
	first, err := client.Do(firstTransaction)
	require.NoError(t, err)
	require.NotNil(t, first.OtherAddr)

	secondTransaction, err := NewBindingTransaction(first.OtherAddr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(testSocketTimeout)))
	second, err := client.Do(secondTransaction)
	require.NoError(t, err)
	require.Equal(t, "198.51.100.1:41001", second.MappedAddr.String())

	firstSource := <-primarySource
	secondSource := <-alternateSource
	require.True(t, firstSource.IP.Equal(secondSource.IP))
	require.Equal(t, firstSource.Port, secondSource.Port)
	require.Equal(t, conn.LocalAddr().(*net.UDPAddr).Port, firstSource.Port)
	waitServer(t, primaryDone)
	waitServer(t, alternateDone)
}

func TestClientValidatesArguments(t *testing.T) {
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}
	transaction, err := NewBindingTransaction(server)
	require.NoError(t, err)

	_, err = NewClient(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-nil UDP connection")

	var nilClient *Client
	_, err = nilClient.Do(transaction)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil STUN Client")

	_, err = (&Client{}).Do(transaction)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no UDP connection")

	conn := listenUDP4(t)
	client, err := NewClient(conn)
	require.NoError(t, err)
	_, err = client.Do(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-nil BindingTransaction")

	var nilTransaction *BindingTransaction
	_, matched, err := nilTransaction.Process(nil, nil)
	require.False(t, matched)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil STUN BindingTransaction")
}

func TestClientPreservesWriteNetError(t *testing.T) {
	conn := listenUDP4(t)
	client, err := NewClient(conn)
	require.NoError(t, err)
	transaction, err := NewBindingTransaction(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478})
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	_, err = client.Do(transaction)
	var netErr net.Error
	require.True(t, errors.As(err, &netErr))
}
