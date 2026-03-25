package net

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDial(t *testing.T) {
	require := require.New(t)

	l, err := net.Listen("tcp", "127.0.0.1:")
	require.NoError(err)

	c, err := Dial(l.Addr().String())
	require.NoError(err)
	require.NotNil(c)
	c.Close()
}

func TestDialTimeout(t *testing.T) {
	require := require.New(t)

	timeout := 200 * time.Millisecond
	start := time.Now()
	c, err := Dial("2.3.3.3:80", WithTimeout(timeout))
	end := time.Now()
	require.Error(err)
	require.Nil(c)
	require.Truef(end.After(start.Add(timeout)), "start: %v, end: %v", start, end)
	require.True(end.Before(start.Add(2*timeout)), "start: %v, end: %v", start, end)
}

func TestHTTPSProxyAutoServerName(t *testing.T) {
	require := require.New(t)

	// Start a TLS server to verify the auto-derived ServerName works
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	require.NoError(err)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(err)
	defer l.Close()

	// Accept one TLS connection and respond with HTTP 200 to CONNECT
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, _ := http.ReadRequest(bufio.NewReader(conn))
		if req != nil && req.Method == "CONNECT" {
			fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		}
	}()

	// Build TLS config with NO ServerName -- it should be auto-derived from proxyAddr
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(localhostCert)
	proxyTLSCfg := &tls.Config{
		RootCAs: certPool,
		// ServerName intentionally left empty
	}

	ctx := context.Background()
	dialMetas := make(DialMetas)
	ctx = context.WithValue(ctx, dialCtxKey, dialMetas)
	dialMetas[proxyTLSConfigKey] = proxyTLSCfg

	rawConn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(err)
	defer rawConn.Close()

	// proxyAddr is "127.0.0.1:<port>" -- but cert has SAN for 127.0.0.1, so this should work
	conn, err := httpsProxyAfterHook(ctx, rawConn, "10.0.0.1:7000", l.Addr().String())
	require.NoError(err)
	require.NotNil(conn)
}

func TestHTTPSProxyTLSHandshakeFailure(t *testing.T) {
	require := require.New(t)

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	require.NoError(err)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(err)
	defer l.Close()

	go func() {
		conn, _ := l.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	// Use an empty RootCAs pool so the self-signed cert is not trusted
	ctx := context.Background()
	dialMetas := make(DialMetas)
	ctx = context.WithValue(ctx, dialCtxKey, dialMetas)

	rawConn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(err)
	defer rawConn.Close()

	_, err = httpsProxyAfterHook(ctx, rawConn, "10.0.0.1:7000", l.Addr().String())
	require.Error(err)
	require.Contains(err.Error(), "TLS handshake with HTTPS proxy")
}

func TestHTTPSProxyAfterHook(t *testing.T) {
	require := require.New(t)

	// Start a TLS server that speaks HTTP CONNECT (simulates an HTTPS proxy)
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	require.NoError(err)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(err)
	defer l.Close()

	// backend target server
	backendL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer backendL.Close()

	go func() {
		conn, err := backendL.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	// proxy handler: accept CONNECT, then pipe to backend
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		if req.Method != "CONNECT" {
			resp := &http.Response{StatusCode: 400, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
			resp.Write(conn)
			return
		}

		// connect to backend
		backend, err := net.Dial("tcp", backendL.Addr().String())
		if err != nil {
			resp := &http.Response{StatusCode: 502, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
			resp.Write(conn)
			return
		}
		defer backend.Close()

		fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

		// bidirectional copy
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				backend.Write(buf[:n])
			}
		}()
		buf := make([]byte, 4096)
		for {
			n, err := backend.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	}()

	// Build a TLS config that trusts our test cert
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(localhostCert)
	proxyTLSCfg := &tls.Config{
		RootCAs:    certPool,
		ServerName: "localhost",
	}

	// Dial through the HTTPS proxy
	ctx := context.Background()
	dialMetas := make(DialMetas)
	ctx = context.WithValue(ctx, dialCtxKey, dialMetas)
	dialMetas[proxyTLSConfigKey] = proxyTLSCfg

	// TCP connect to the TLS proxy
	rawConn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(err)
	defer rawConn.Close()

	// Run the https proxy hook which does TLS + CONNECT
	conn, err := httpsProxyAfterHook(ctx, rawConn, backendL.Addr().String(), l.Addr().String())
	require.NoError(err)
	require.NotNil(conn)

	// Verify data flows through the tunnel
	_, err = conn.Write([]byte("hello"))
	require.NoError(err)

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	require.NoError(err)
	require.Equal("hello", string(buf[:n]))
}

// Self-signed cert for localhost testing (generated for test use only).
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBijCCATCgAwIBAgIBATAKBggqhkjOPQQDAjAUMRIwEAYDVQQDEwlsb2NhbGhv
c3QwHhcNMjYwMzI1MTE1MTIzWhcNMzYwMzIyMTI1MTIzWjAUMRIwEAYDVQQDEwls
b2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATr8o40uWZXI0ILr36n
UtZIeY/7X/mN44kYp1eFubnu1PtCMn0oRoI7XMLtb7ZH92fkzZQNJp3SqG7ntGC3
MONao3MwcTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYD
VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUo3ixEmbOr6h+yl49udjuFp0GnSQwGgYD
VR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0gAMEUCIBJqFcYA
bOUh2xhwwiNAJYf+ndsLQwcG/Xvq6vh0pgJRAiEA5Q3XUs0jcHwiXxsDulXCCP5m
ezw1NQfI1c+EHa4NGzk=
-----END CERTIFICATE-----
`)

var localhostKey = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOBWZAzhhtudR+FUfk2QY4+tCLix4s+vMiQOx/Vi6fKBoAoGCCqGSM49
AwEHoUQDQgAE6/KONLlmVyNCC69+p1LWSHmP+1/5jeOJGKdXhbm57tT7QjJ9KEaC
O1zC7W+2R/dn5M2UDSad0qhu57RgtzDjWg==
-----END EC PRIVATE KEY-----
`)
