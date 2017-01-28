package main

import (
	"crypto/x509"
	"github.com/adamdecaf/cert-manage/certs"
	"io/ioutil"
	"net/http"
	"sync"
)

// Pull ASN.1 DER encoded certificates
type derCerts struct {
	fingerprints, urls []string
}
func (c derCerts) Pull() []*x509.Certificate {
	bs := load(c.urls)

	cs := make([]*x509.Certificate, 0)
	for _, c := range bs {
		cert, err := x509.ParseCertificates(c)
		if err != nil {
			return nil
		}
		cs = append(cs, cert...)
	}
	return filter(c.fingerprints, cs)
}

// Pull PEM encoded certs
type pemCerts struct {
	fingerprints, urls []string
}
func (c pemCerts) Pull() []*x509.Certificate {
	bs := load(c.urls)

	cs := make([]*x509.Certificate, 0)
	for _, c := range bs {
		cert, err := certs.ParsePEMIntoCerts(c)
		if err != nil {
			return nil
		}
		cs = append(cs, cert...)
	}
	return filter(c.fingerprints, cs)
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
