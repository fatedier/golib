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
	"context"
	"fmt"
	"net"
	"sort"

	"github.com/fatedier/kcp-go"
)

func Dial(addr string, opts ...DialOption) (c net.Conn, err error) {
	return DialContext(context.Background(), addr, opts...)
}

func DialContext(ctx context.Context, addr string, opts ...DialOption) (c net.Conn, err error) {
	op := defaultDialOptions()

	for _, opt := range opts {
		opt.apply(&op)
	}

	// call before dial hooks
	dialMetas := make(DialMetas)
	ctx = context.WithValue(ctx, ctxKey, dialMetas)

	for _, v := range op.beforeHooks {
		ctx = v.Hook(ctx, addr)
	}

	if op.proxyAddr != "" {
		support := false
		for _, v := range supportProxyTypes {
			if op.proxyType == v {
				support = true
				break
			}
		}
		if !support {
			return nil, fmt.Errorf("ProxyType must be http or socks5 or ntlm, not [%s]", op.proxyType)
		}
	}

	// dial a new connection
	dstAddr := addr
	if op.proxyAddr != "" {
		dstAddr = op.proxyAddr
	}

	if op.dialer != nil {
		c, err = op.dialer(ctx, dstAddr)
	} else {
		c, err = dial(ctx, dstAddr, op)
	}
	if err != nil {
		return nil, err
	}

	// call after dial hooks
	sort.SliceStable(op.afterHooks, func(i, j int) bool {
		return op.afterHooks[i].Priority < op.afterHooks[j].Priority
	})

	lastSuccConn := c
	for _, v := range op.afterHooks {
		ctx, c, err = v.Hook(ctx, c, addr)
		if err != nil {
			// Close last valid connection if any error occured
			lastSuccConn.Close()
			return nil, err
		}
		lastSuccConn = c
	}
	return
}

func dial(ctx context.Context, addr string, op dialOptions) (c net.Conn, err error) {
	switch op.protocol {
	case "tcp":
		dialer := &net.Dialer{
			Timeout:   op.timeout,
			KeepAlive: op.keepAlive,
		}
		if op.laddr != "" {
			if tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:", op.laddr)); err == nil {
				dialer.LocalAddr = tcpAddr
			}
		}
		return dialer.DialContext(ctx, "tcp", addr)
	case "kcp":
		return dialKCPServer(addr)
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", op.protocol)
	}
}

func dialKCPServer(addr string) (c net.Conn, err error) {
	kcpConn, errRet := kcp.DialWithOptions(addr, nil, 10, 3)
	if errRet != nil {
		err = errRet
		return
	}
	kcpConn.SetStreamMode(true)
	kcpConn.SetWriteDelay(true)
	kcpConn.SetNoDelay(1, 20, 2, 1)
	kcpConn.SetWindowSize(128, 512)
	kcpConn.SetMtu(1350)
	kcpConn.SetACKNoDelay(false)
	kcpConn.SetReadBuffer(4194304)
	kcpConn.SetWriteBuffer(4194304)
	c = kcpConn
	return
}
