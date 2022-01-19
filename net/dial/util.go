package dial

import (
	"net/url"
)

func ParseProxyURL(proxyURL string) (proxyType string, address string, auth *ProxyAuth, err error) {
	var u *url.URL
	if u, err = url.Parse(proxyURL); err != nil {
		return
	}

	if u.User != nil {
		auth = &ProxyAuth{}
		auth.Username = u.User.Username()
		auth.Passwd, _ = u.User.Password()
	}
	return u.Scheme, u.Host, auth, nil
}
