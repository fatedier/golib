package net

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
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
	cert, certPool := newLocalhostTestCertificate(t)

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

func TestHTTPSProxyAutoServerNameWithInsecureSkipVerify(t *testing.T) {
	require := require.New(t)

	cert, _ := newLocalhostTestCertificate(t)

	tlsConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.ServerName != "localhost" {
				return nil, fmt.Errorf("unexpected SNI %q", hello.ServerName)
			}
			return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
		},
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(err)
	defer l.Close()

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

	proxyTLSCfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	ctx := context.Background()
	dialMetas := make(DialMetas)
	ctx = context.WithValue(ctx, dialCtxKey, dialMetas)
	dialMetas[proxyTLSConfigKey] = proxyTLSCfg

	rawConn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(err)
	defer rawConn.Close()

	conn, err := httpsProxyAfterHook(ctx, rawConn, "10.0.0.1:7000", "localhost:"+fmt.Sprint(l.Addr().(*net.TCPAddr).Port))
	require.NoError(err)
	require.NotNil(conn)
}

func TestHTTPSProxyTLSHandshakeFailure(t *testing.T) {
	require := require.New(t)

	cert, _ := newLocalhostTestCertificate(t)

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
	const timeout = 5 * time.Second
	payload := []byte("hello")
	errCh := make(chan error, 2)

	// Start a TLS server that speaks HTTP CONNECT (simulates an HTTPS proxy)
	cert, certPool := newLocalhostTestCertificate(t)

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
			errCh <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		_, err = conn.Write(buf)
		errCh <- err
	}()

	// proxy handler: accept CONNECT, then pipe to backend
	go func() {
		conn, err := l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			errCh <- err
			return
		}

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			errCh <- err
			return
		}
		if req.Method != "CONNECT" {
			errCh <- fmt.Errorf("unexpected method %q", req.Method)
			return
		}

		// connect to backend
		backend, err := net.Dial("tcp", backendL.Addr().String())
		if err != nil {
			errCh <- err
			return
		}
		defer backend.Close()
		if err := backend.SetDeadline(time.Now().Add(timeout)); err != nil {
			errCh <- err
			return
		}

		if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			errCh <- err
			return
		}

		if _, err := io.CopyN(backend, conn, int64(len(payload))); err != nil {
			errCh <- err
			return
		}
		_, err = io.CopyN(conn, backend, int64(len(payload)))
		errCh <- err
	}()

	// Build a TLS config that trusts our test cert
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
	require.NoError(rawConn.SetDeadline(time.Now().Add(timeout)))

	// Run the https proxy hook which does TLS + CONNECT
	conn, err := httpsProxyAfterHook(ctx, rawConn, backendL.Addr().String(), l.Addr().String())
	require.NoError(err)
	require.NotNil(conn)
	defer conn.Close()
	require.NoError(conn.SetDeadline(time.Now().Add(timeout)))

	// Verify data flows through the tunnel
	_, err = conn.Write(payload)
	require.NoError(err)

	buf := make([]byte, len(payload))
	n, err := io.ReadFull(conn, buf)
	require.NoError(err)
	require.Equal(payload, buf[:n])

	waitErr := func() error {
		select {
		case err := <-errCh:
			return err
		case <-time.After(timeout):
			return fmt.Errorf("timeout waiting for proxy test goroutine")
		}
	}
	require.NoError(waitErr())
	require.NoError(waitErr())
}

func TestNTLMHTTPProxyAfterHookUsesUsernameDirectly(t *testing.T) {
	require := require.New(t)
	const timeout = 5 * time.Second

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	require.NoError(clientConn.SetDeadline(time.Now().Add(timeout)))
	require.NoError(serverConn.SetDeadline(time.Now().Add(timeout)))

	errCh := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)

		req, err := http.ReadRequest(reader)
		if err != nil {
			errCh <- err
			return
		}
		if req.Method != "CONNECT" {
			errCh <- fmt.Errorf("unexpected method %q", req.Method)
			return
		}

		negotiateHeader := req.Header.Get("Proxy-Authorization")
		if negotiateHeader == "" {
			errCh <- fmt.Errorf("missing Proxy-Authorization on negotiate request")
			return
		}
		negotiateMessage, err := decodeNTLMNegotiateHeader(negotiateHeader)
		if err != nil {
			errCh <- err
			return
		}
		if len(negotiateMessage) < 40 {
			errCh <- fmt.Errorf("negotiate message too short: %d", len(negotiateMessage))
			return
		}
		flags := binary.LittleEndian.Uint32(negotiateMessage[12:16])
		if flags&ntlmNegotiateOEMDomainSupplied != 0 {
			errCh <- fmt.Errorf("unexpected OEM domain supplied flag in negotiate message")
			return
		}
		if bytes.Contains(negotiateMessage[40:], []byte("DOMAIN")) {
			errCh <- fmt.Errorf("unexpected user domain in negotiate payload")
			return
		}

		challenge, err := createNTLMTestChallenge()
		if err != nil {
			errCh <- err
			return
		}
		challengeResp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Negotiate " + challenge + "\r\n" +
			"Content-Length: 0\r\n\r\n"
		if _, err := fmt.Fprint(serverConn, challengeResp); err != nil {
			errCh <- err
			return
		}

		req, err = http.ReadRequest(reader)
		if err != nil {
			errCh <- err
			return
		}
		authenticateHeader := req.Header.Get("Proxy-Authorization")
		if authenticateHeader == "" {
			errCh <- fmt.Errorf("missing Proxy-Authorization on authenticate request")
			return
		}
		authenticateMessage, err := decodeNTLMNegotiateHeader(authenticateHeader)
		if err != nil {
			errCh <- err
			return
		}
		if len(authenticateMessage) < 8 || !bytes.Equal(authenticateMessage[:8], []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}) {
			errCh <- fmt.Errorf("unexpected NTLM authenticate message signature")
			return
		}

		_, err = fmt.Fprintf(serverConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		errCh <- err
	}()

	ctx := context.Background()
	dialMetas := make(DialMetas)
	ctx = context.WithValue(ctx, dialCtxKey, dialMetas)
	dialMetas[proxyAuthKey] = &ProxyAuth{
		Username: `DOMAIN\alice`,
		Passwd:   "password",
	}

	conn, err := ntlmHTTPProxyAfterHook(ctx, clientConn, "10.0.0.1:7000")
	require.NoError(err)
	require.NotNil(conn)

	select {
	case err := <-errCh:
		require.NoError(err)
	case <-time.After(timeout):
		t.Fatal("timeout waiting for NTLM proxy test goroutine")
	}
}

const ntlmNegotiateOEMDomainSupplied uint32 = 1 << 12

func decodeNTLMNegotiateHeader(header string) ([]byte, error) {
	const prefix = "Negotiate "
	if !strings.HasPrefix(header, prefix) {
		return nil, fmt.Errorf("unexpected negotiate header %q", header)
	}
	return base64.StdEncoding.DecodeString(header[len(prefix):])
}

type ntlmTestMessageHeader struct {
	Signature   [8]byte
	MessageType uint32
}

type ntlmTestVarField struct {
	Len          uint16
	MaxLen       uint16
	BufferOffset uint32
}

type ntlmTestChallengeMessageFields struct {
	MessageHeader   ntlmTestMessageHeader
	TargetName      ntlmTestVarField
	NegotiateFlags  uint32
	ServerChallenge [8]byte
	Reserved        [8]byte
	TargetInfo      ntlmTestVarField
}

func createNTLMTestChallenge() (string, error) {
	msg := ntlmTestChallengeMessageFields{
		MessageHeader: ntlmTestMessageHeader{
			Signature:   [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0},
			MessageType: 2,
		},
		NegotiateFlags:  0xa0888201,
		ServerChallenge: [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &msg); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func newLocalhostTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	certPool := x509.NewCertPool()
	require.True(t, certPool.AppendCertsFromPEM(certPEM))

	return cert, certPool
}
