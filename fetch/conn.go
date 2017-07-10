package fetch

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adamdecaf/cert-manage/tools/_tls"
)

// GetConnCert fetches the cert presented by a connection to the host/port pulled from
// the provided in url.
// If the url is invalid an error is returned, otherwise the cert is given back and nil error.
func GetConnCert(raw string) (*x509.Certificate, error) {
	if !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, fmt.Errorf("error parsing url '%s'", raw)
	}

	return getConnCert(*parsed)
}

//
func getConnCert(u url.URL) (*x509.Certificate, error) {
	addr := fmt.Sprintf("%s:%s", u.Hostname(), u.Port())
	// If Hostname or Port are empty then the uri looks like 'host:'
	if strings.HasPrefix(addr, ":") || strings.HasSuffix(addr, ":") {
		return nil, fmt.Errorf("error - missing host/port in url, %s", u.String())
	}

	// Establish the tls/http conn just enough to be presented the cert
	// TODO(adam): Present the conn more like an actual browser,
	//  - change: useragent, header ordering, versions, cipher suites
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			},
			TLSHandshakeTimeout: 1*time.Minute,
			IdleConnTimeout: 1*time.Minute,
			ResponseHeaderTimeout: 1*time.Minute,
			ExpectContinueTimeout: 1*time.Minute,
		},
	}
	resp, err := client.Get(u.String())
	if err != nil {
		return nil, err
	}

	// Pull out the useful information, then close.
	state := resp.TLS
	fmt.Printf("version - %s\n", _tls.Ver2String(state.Version))
	fmt.Printf("cipher suite - %d\n", state.CipherSuite)
	fmt.Printf("server name - %s\n", state.ServerName)
	// state.PeerCertificates []*x509.Certificate
	// state.VerifiedChains   [][]*x509.Certificate

	// TODO(adam): return child cert
	return nil, nil
}
