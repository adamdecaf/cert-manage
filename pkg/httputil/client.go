package httputil

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

var (
	// https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
	client = &http.Client{
		// Never follow redirects, return body
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			},
			TLSHandshakeTimeout:   1 * time.Minute,
			IdleConnTimeout:       1 * time.Minute,
			ResponseHeaderTimeout: 1 * time.Minute,
			ExpectContinueTimeout: 1 * time.Minute,
		},
		Timeout: 30 * time.Second,
	}
)

func New() *http.Client {
	return client
}
