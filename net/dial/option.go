// Copyright 2018 fatedier, fatedier@gmail.com
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

package dial

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
	"golang.org/x/net/proxy"
)

var (
	supportProxyTypes = []string{"socks5", "http", "ntlm"}
)

type ProxyAuth struct {
	Username string
	Passwd   string
}

type DialMetas map[interface{}]interface{}

func (m DialMetas) Value(key interface{}) interface{} {
	return m[key]
}

type metaKey string

const (
	ctxKey       metaKey = "meta"
	proxyAuthKey metaKey = "proxyAuth"
)

func GetDialMetasFromContext(ctx context.Context) DialMetas {
	metas, ok := ctx.Value(ctxKey).(DialMetas)
	if !ok || metas == nil {
		metas = make(DialMetas)
	}
	return metas
}

type dialOptions struct {
	proxyType string
	proxyAddr string
	protocol  string
	tlsConfig *tls.Config
	laddr     string // only use ip, port is random
	timeout   time.Duration
	keepAlive time.Duration

	dialer func(ctx context.Context, addr string) (c net.Conn, err error)

	afterHooks  []AfterHook
	beforeHooks []BeforeHook
}

type BeforeHookFunc func(ctx context.Context, addr string) context.Context

type BeforeHook struct {
	Hook BeforeHookFunc
}

const (
	DefaultAfterHookPriority = 10
)

type AfterHookFunc func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error)

type AfterHook struct {
	// smaller value will be called first, 0 is reserverd for private use.
	// If caller set this 0, use DefaultAfterHookPriority instead.
	Priority uint64
	Hook     AfterHookFunc
}

type DialOption interface {
	apply(*dialOptions)
}

type funcDialOption struct {
	f func(*dialOptions)
}

func (fdo *funcDialOption) apply(do *dialOptions) {
	fdo.f(do)
}

func newFuncDialOption(f func(*dialOptions)) *funcDialOption {
	return &funcDialOption{
		f: f,
	}
}

func defaultDialOptions() dialOptions {
	return dialOptions{
		protocol: "tcp",
		timeout:  30 * time.Second,
	}
}

func WithProxy(proxyType string, address string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		if proxyType == "" && address == "" {
			return
		}

		do.proxyType = proxyType
		do.proxyAddr = address

		var hook func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error)
		switch proxyType {
		case "socks5":
			hook = func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
				conn, err := socks5ProxyAfterHook(ctx, c, addr)
				return ctx, conn, err
			}
		case "http":
			hook = func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
				conn, err := httpProxyAfterHook(ctx, c, addr)
				return ctx, conn, err
			}
		case "ntlm":
			hook = func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
				conn, err := ntlmHTTPProxyAfterHook(ctx, c, addr)
				return ctx, conn, err
			}
		}

		if hook != nil {
			do.afterHooks = append(do.afterHooks, AfterHook{
				Priority: 0,
				Hook:     hook,
			})
		}
	})
}

func WithProxyAuth(auth *ProxyAuth) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.beforeHooks = append(do.beforeHooks, BeforeHook{
			Hook: func(ctx context.Context, addr string) context.Context {
				metas := GetDialMetasFromContext(ctx)
				metas[proxyAuthKey] = auth
				return ctx
			},
		})
	})
}

func WithTLSConfig(tlsConfig *tls.Config) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		if tlsConfig == nil {
			return
		}

		do.afterHooks = append(do.afterHooks, AfterHook{
			Priority: math.MaxUint64,
			Hook: func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
				conn, err := tlsAfterHook(c, tlsConfig)
				return ctx, conn, err
			},
		})
	})
}

func WithProtocol(protocol string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.protocol = protocol
	})
}

func WithLocalAddr(laddr string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.laddr = laddr
	})
}

func WithTimeout(timeout time.Duration) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.timeout = timeout
	})
}

func WithKeepAlive(keepAlive time.Duration) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.keepAlive = keepAlive
	})
}

func WithAfterHook(hook AfterHook) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.afterHooks = append(do.afterHooks, hook)
	})
}

func newSocks5ProxyAfterHook(addr string, op dialOptions) AfterHook {
	return AfterHook{
		Priority: 0,
		Hook: func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
			conn, err := socks5ProxyAfterHook(ctx, c, addr)
			return ctx, conn, err
		},
	}
}

func newNTLMHTTPProxyAfterHook(addr string, op dialOptions) AfterHook {
	return AfterHook{
		Priority: 0,
		Hook: func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
			conn, err := ntlmHTTPProxyAfterHook(ctx, c, addr)
			return ctx, conn, err
		},
	}
}

type funcDialContext func(ctx context.Context, networkd string, addr string) (c net.Conn, err error)

func (fdc funcDialContext) DialContext(ctx context.Context, network string, addr string) (c net.Conn, err error) {
	return fdc(ctx, network, addr)
}

func (fdc funcDialContext) Dial(network string, addr string) (c net.Conn, err error) {
	return fdc(context.Background(), network, addr)
}

func socks5ProxyAfterHook(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	meta := GetDialMetasFromContext(ctx)
	proxyAuth, _ := meta.Value(proxyAuthKey).(*ProxyAuth)

	var s5Auth *proxy.Auth
	if proxyAuth != nil {
		s5Auth = &proxy.Auth{
			User:     proxyAuth.Username,
			Password: proxyAuth.Passwd,
		}
	}

	// We don't use address here because we always return an existing connection and ignore it
	dialer, err := proxy.SOCKS5("tcp", "", s5Auth, funcDialContext(func(_ context.Context, network string, addr string) (net.Conn, error) {
		return conn, nil
	}))
	if err != nil {
		return nil, err
	}

	c, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func httpProxyAfterHook(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	meta := GetDialMetasFromContext(ctx)
	proxyAuth, _ := meta.Value(proxyAuthKey).(*ProxyAuth)

	req, err := http.NewRequest("CONNECT", "http://"+addr, nil)
	if err != nil {
		return nil, err
	}
	if proxyAuth != nil {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxyAuth.Username+":"+proxyAuth.Passwd)))
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Write(conn)

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DialTcpByHttpProxy error, StatusCode [%d]", resp.StatusCode)
	}

	return conn, nil
}

func ntlmHTTPProxyAfterHook(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	meta := GetDialMetasFromContext(ctx)
	proxyAuth, _ := meta.Value(proxyAuthKey).(*ProxyAuth)

	req, err := http.NewRequest("CONNECT", "http://"+addr, nil)
	if err != nil {
		return nil, err
	}
	if proxyAuth != nil {
		domain := ""
		_, domain = ntlmssp.GetDomain(proxyAuth.Username)
		negotiateMessage, err := ntlmssp.NewNegotiateMessage(domain, "")
		if err != nil {
			return nil, err
		}
		req.Header.Add("Proxy-Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negotiateMessage))
	}

	req.Write(conn)
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	if proxyAuth != nil && resp.StatusCode == 407 {
		challenge := resp.Header.Get("Proxy-Authenticate")
		username, _ := ntlmssp.GetDomain(proxyAuth.Username)

		if strings.HasPrefix(challenge, "Negotiate ") {
			challengeMessage, err := base64.StdEncoding.DecodeString(challenge[len("Negotiate "):])
			if err != nil {
				return nil, err
			}
			authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, username, proxyAuth.Passwd)
			if err != nil {
				return nil, err
			}
			req, err := http.NewRequest("CONNECT", "http://"+addr, nil)
			if err != nil {
				return nil, err
			}

			req.Header.Add("Proxy-Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authenticateMessage))
			req.Write(conn)
			resp, err = http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				return nil, err
			}
			resp.Body.Close()
		}
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DialTcpByNTLMHttpProxy error, StatusCode [%d]", resp.StatusCode)
	}

	return conn, nil
}

func tlsAfterHook(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	if tlsConfig == nil {
		return conn, nil
	}
	return tls.Client(conn, tlsConfig), nil
}
