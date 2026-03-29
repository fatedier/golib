package net

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustTestProxyURL(t *testing.T, scheme, username, passwd, host string) string {
	t.Helper()

	u := &url.URL{
		Scheme: scheme,
		Host:   host,
		User:   url.UserPassword(username, passwd),
	}
	return u.String()
}

func TestParseProxyURL(t *testing.T) {
	require := require.New(t)

	tests := []struct {
		proxyURL string

		expectProxyType string
		expectAddress   string
		expectAuth      *ProxyAuth
		expectErr       bool
	}{
		{
			proxyURL:        "http://127.0.0.1",
			expectProxyType: "http",
			expectAddress:   "127.0.0.1",
		},
		{
			proxyURL:        mustTestProxyURL(t, "http", "admin", "abc", "127.0.0.1:8080"),
			expectProxyType: "http",
			expectAddress:   "127.0.0.1:8080",
			expectAuth: &ProxyAuth{
				Username: "admin",
				Passwd:   "abc",
			},
		},
		{
			proxyURL:        "socks5://admin:abc@127.0.0.1:9000",
			expectProxyType: "socks5",
			expectAddress:   "127.0.0.1:9000",
			expectAuth: &ProxyAuth{
				Username: "admin",
				Passwd:   "abc",
			},
		},
		{
			proxyURL:        mustTestProxyURL(t, "https", "admin", "abc", "127.0.0.1:8443"),
			expectProxyType: "https",
			expectAddress:   "127.0.0.1:8443",
			expectAuth: &ProxyAuth{
				Username: "admin",
				Passwd:   "abc",
			},
		},
		{
			proxyURL:  "http://127.0.0.1:8080@admin:abc",
			expectErr: true,
		},
	}

	for i, test := range tests {
		proxyType, address, auth, err := ParseProxyURL(test.proxyURL)
		if test.expectErr {
			require.Errorf(err, "case %d", i)
		} else {
			require.NoErrorf(err, "case %d", i)
		}
		require.EqualValuesf(test.expectProxyType, proxyType, "case %d", i)
		require.EqualValuesf(test.expectAddress, address, "case %d", i)
		require.EqualValuesf(test.expectAuth, auth, "case %d", i)
	}
}
