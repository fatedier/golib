package mux

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func runHTTPSvr(ln net.Listener) *httptest.Server {
	svr := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("http service"))
	}))
	svr.Listener = ln
	svr.Start()
	return svr
}

func runHTTPSSvr(ln net.Listener) *httptest.Server {
	svr := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("https service"))
	}))
	svr.Listener = ln
	svr.StartTLS()
	return svr
}

func runEchoSvr(ln net.Listener) {
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			rd := bufio.NewReader(conn)
			data, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			conn.Write([]byte(data))
			conn.Close()
		}
	}()
}

func runTCPSvr(ln net.Listener, respContent string) {
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			rd := bufio.NewReader(conn)
			_, err = rd.ReadString('\n')
			if err != nil {
				return
			}
			conn.Write([]byte(respContent))
			conn.Close()
		}
	}()
}

func TestMux(t *testing.T) {
	assert := assert.New(t)

	ln, err := net.Listen("tcp", "127.0.0.1:")
	assert.NoError(err)

	mux := NewMux(ln)
	httpLn := mux.ListenHTTP(0)
	httpsLn := mux.ListenHTTPS(0)
	defaultLn := mux.DefaultListener()
	go mux.Serve()
	time.Sleep(100 * time.Millisecond)

	httpSvr := runHTTPSvr(httpLn)
	defer httpSvr.Close()
	httpsSvr := runHTTPSSvr(httpsLn)
	defer httpsSvr.Close()
	runEchoSvr(defaultLn)
	defer ln.Close()

	// test http service
	resp, err := http.Get(httpSvr.URL)
	assert.NoError(err)
	data, err := io.ReadAll(resp.Body)
	assert.NoError(err)
	assert.Equal("http service", string(data))

	// test https service
	client := httpsSvr.Client()
	resp, err = client.Get(httpsSvr.URL)
	assert.NoError(err)
	data, err = io.ReadAll(resp.Body)
	assert.NoError(err)
	assert.Equal("https service", string(data))

	// test echo service
	conn, err := net.Dial("tcp", ln.Addr().String())
	assert.NoError(err)
	_, err = conn.Write([]byte("test echo\n"))
	assert.NoError(err)
	data = make([]byte, 1024)
	n, err := conn.Read(data)
	assert.NoError(err)
	assert.Equal("test echo\n", string(data[:n]))
}

func TestMuxPriority(t *testing.T) {
	assert := assert.New(t)

	ln, err := net.Listen("tcp", "127.0.0.1:")
	assert.NoError(err)

	mux := NewMux(ln)
	ln1 := mux.Listen(0, 2, func(data []byte) bool {
		return data[0] == '1'
	})
	ln2 := mux.Listen(1, 2, func(data []byte) bool {
		return data[0] == '1'
	})
	runTCPSvr(ln1, "aaa")
	runTCPSvr(ln2, "bbb")
	go mux.Serve()
	time.Sleep(100 * time.Millisecond)

	// priority 0, '1' -> 'aaa'
	// priority 1, '1' -> 'bbb'
	conn, err := net.Dial("tcp", ln.Addr().String())
	assert.NoError(err)
	_, err = conn.Write([]byte("111\n"))
	assert.NoError(err)
	data := make([]byte, 1024)
	n, err := conn.Read(data)
	assert.NoError(err)
	assert.Equal("aaa", string(data[:n]))

	// No match
	ln1.Close()
	ln2.Close()
	conn, err = net.Dial("tcp", ln.Addr().String())
	assert.NoError(err)
	_, err = conn.Write([]byte("111\n"))
	assert.NoError(err)
	data = make([]byte, 1024)
	_, err = conn.Read(data)
	assert.Error(err)

	// priority 0, '1' -> 'bbb'
	// priority 1, '1' -> 'aaa'
	ln1 = mux.Listen(0, 2, func(data []byte) bool {
		return data[0] == '1'
	})
	ln2 = mux.Listen(1, 2, func(data []byte) bool {
		return data[0] == '2'
	})
	runTCPSvr(ln2, "aaa")
	runTCPSvr(ln1, "bbb")

	conn, err = net.Dial("tcp", ln.Addr().String())
	assert.NoError(err)
	_, err = conn.Write([]byte("111\n"))
	assert.NoError(err)
	data = make([]byte, 1024)
	n, err = conn.Read(data)
	assert.NoError(err)
	assert.Equal("bbb", string(data[:n]))
}

func TestHTTPMatchFunc(t *testing.T) {
	require.Equal(t, uint32(3), HTTPNeedBytesNum)

	tests := []struct {
		name string
		data string
		want bool
	}{
		{name: "GET", data: "GET / HTTP/1.1\r\n\r\n", want: true},
		{name: "HEAD", data: "HEAD / HTTP/1.1\r\n\r\n", want: true},
		{name: "POST", data: "POST / HTTP/1.1\r\n\r\n", want: true},
		{name: "PUT", data: "PUT / HTTP/1.1\r\n\r\n", want: true},
		{name: "DELETE", data: "DELETE / HTTP/1.1\r\n\r\n", want: true},
		{name: "CONNECT", data: "CONNECT example.com:443 HTTP/1.1\r\n\r\n", want: true},
		{name: "OPTIONS", data: "OPTIONS * HTTP/1.1\r\n\r\n", want: true},
		{name: "TRACE", data: "TRACE / HTTP/1.1\r\n\r\n", want: true},
		{name: "PATCH", data: "PATCH / HTTP/1.1\r\n\r\n", want: true},
		{name: "HTTP/2 client preface", data: http2ClientPreface, want: true},
		{name: "PRI prefix", data: "PRI", want: true},
		{name: "non HTTP", data: "SSH-2.0-client\r\n"},
		{name: "empty", data: ""},
		{name: "short P", data: "P"},
		{name: "short PR", data: "PR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, HTTPMatchFunc([]byte(tt.data)))
		})
	}
}

func TestHTTPListenerPriorKnowledgeRouting(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantRoute string
	}{
		{
			name:      "HTTP/1 through HTTP listener",
			data:      "GET / HTTP/1.1\r\n\r\n",
			wantRoute: "http",
		},
		{
			name:      "full HTTP/2 preface through HTTP listener",
			data:      http2ClientPreface,
			wantRoute: "http",
		},
		{
			name:      "non HTTP through default listener",
			data:      "SSH-2.0-client\r\n",
			wantRoute: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testMuxRoute(t, tt.data, tt.wantRoute)
		})
	}
}

func testMuxRoute(t *testing.T, data, wantRoute string) {
	t.Helper()

	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mux := NewMux(baseLn)
	httpLn := mux.ListenHTTP(0)
	defaultLn := mux.DefaultListener()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- mux.Serve()
	}()

	var clientConn net.Conn
	defer func() {
		if clientConn != nil {
			_ = clientConn.Close()
		}
		_ = httpLn.Close()
		_ = defaultLn.Close()
		_ = mux.Close()
		select {
		case err := <-serveErr:
			assert.ErrorIs(t, err, net.ErrClosed)
		case <-time.After(time.Second):
			assert.Fail(t, "Mux.Serve did not return after Mux.Close")
		}
	}()

	type routeResult struct {
		route string
		data  []byte
		err   error
	}
	resultCh := make(chan routeResult, 2)
	accept := func(route string, ln net.Listener) {
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				resultCh <- routeResult{route: route, err: err}
				return
			}
			defer conn.Close()

			received := make([]byte, len(data))
			_, err = io.ReadFull(conn, received)
			resultCh <- routeResult{route: route, data: received, err: err}
		}()
	}
	accept("http", httpLn)
	accept("default", defaultLn)

	clientConn, err = net.DialTimeout("tcp", baseLn.Addr().String(), time.Second)
	require.NoError(t, err)
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(time.Second)))
	n, err := clientConn.Write([]byte(data))
	require.NoError(t, err)
	require.Equal(t, len(data), n)

	select {
	case result := <-resultCh:
		require.NoError(t, result.err)
		require.Equal(t, wantRoute, result.route)
		// SharedConn must replay the three classification bytes so the backend
		// receives the complete HTTP request or HTTP/2 preface for validation.
		require.Equal(t, []byte(data), result.data)
	case <-time.After(time.Second):
		require.Fail(t, "connection was not routed")
	}
}

func TestDefaultListenerCloseUnblocksAccept(t *testing.T) {
	assert := assert.New(t)

	ln, err := net.Listen("tcp", "127.0.0.1:")
	assert.NoError(err)
	defer ln.Close()

	mux := NewMux(ln)
	defaultLn := mux.DefaultListener()

	done := make(chan error, 1)
	go func() {
		_, err := defaultLn.Accept()
		done <- err
	}()

	err = defaultLn.Close()
	assert.NoError(err)

	select {
	case err := <-done:
		assert.Error(err)
	case <-time.After(time.Second):
		assert.Fail("Accept did not return after DefaultListener.Close")
	}
}
