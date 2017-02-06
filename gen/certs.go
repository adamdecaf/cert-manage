package main

import (
	"crypto/x509"
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
	"io/ioutil"
	"net/http"
	"sync"
)

// Pull ASN.1 DER encoded certificates
type derCerts struct {
	fingerprints, urls []string
}
func (c derCerts) Pull() ([]*x509.Certificate, error) {
	bs := load(c.urls)

	cs := make([]*x509.Certificate, 0)
	for _, c := range bs {
		cert, err := x509.ParseCertificates(c)
		if err != nil {
			return nil, fmt.Errorf("error parsing der cert")
		}
		cs = append(cs, cert...)
	}

	if len(cs) != len(c.fingerprints) {
		return nil, fmt.Errorf("pulled %d certs, but expected %d", len(cs), len(c.fingerprints))
	}
	if len(c.fingerprints) != len(c.urls) {
		return nil, fmt.Errorf("%d expected fingerprints doesn't match %d expected urls", len(c.fingerprints), len(c.urls))
	}

	return filter(c.fingerprints, cs), nil
}

// Pull PEM encoded certs
type pemCerts struct {
	fingerprints, urls []string
}
func (c pemCerts) Pull() ([]*x509.Certificate, error) {
	bs := load(c.urls)

	cs := make([]*x509.Certificate, 0)
	for _, c := range bs {
		cert, err := certs.ParsePEMIntoCerts(c)
		if err != nil {
			return nil, fmt.Errorf("error parsing pem cert")
		}
		cs = append(cs, cert...)
	}

	if len(cs) != len(c.fingerprints) {
		return nil, fmt.Errorf("pulled %d certs, but expected %d", len(cs), len(c.fingerprints))
	}
	if len(c.fingerprints) != len(c.urls) {
		return nil, fmt.Errorf("%d expected fingerprints doesn't match %d expected urls", len(c.fingerprints), len(c.urls))
	}

	return filter(c.fingerprints, cs), nil
}

// Load all raw cert data from the remote sources
func load(urls []string) [][]byte {
	mu := sync.Mutex{}
	wait := sync.WaitGroup{}
	wait.Add(len(urls))

	out := make([][]byte, 0)
	for _,u := range urls {
		go func(url string)  {
			mu.Lock()
			defer mu.Unlock()
			defer wait.Done()

			b := readRemoteData(url)
			if len(b) > 0 {
				out = append(out, b)
			}
		}(u)
	}

	wait.Wait()
	return out
}

// Keep certificates that match the fingerprint whitelist
func filter(fingerprints []string, cs []*x509.Certificate) []*x509.Certificate {
	// If we don't have fingerprints to check against, just return all certs.
	if len(fingerprints) == 0 {
		return cs
	}

	wh := make([]certs.WhitelistItem, len(fingerprints))
	for i := range fingerprints {
		wh[i] = certs.HexFingerprintWhitelistItem{Signature: fingerprints[i]}
	}
	return certs.Filter(cs, wh)
}

// Load the raw cert data from the remote
func readRemoteData(url string) []byte {
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return b
}
