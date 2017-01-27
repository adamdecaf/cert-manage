package main

import (
	"crypto/x509"
	"github.com/adamdecaf/cert-manage/certs"
	"io/ioutil"
	"net/http"
	"sync"
)

const (
	SponsoredTrustedRootsUrl = "https://pki.goog/roots.pem"
)

// This is a list of roots suggested by Google as certs to trust.
// It's pulled from https://pki.goog/roots.pem
func GoogleSuggestedRoots() []*x509.Certificate {
	certs := make([]*x509.Certificate, 0)

	return certs
}

// Returns the Google owned CA certs
// These are copied from https://pki.goog/
func Google() []*x509.Certificate {
	var fingerprints = make(map[string]string)
	fingerprints["https://pki.goog/gsr2/GSR2.crt"] = "75e0abb6138512271c04f85fddde38e4b7242efe"
	fingerprints["https://pki.goog/gsr4/GSR4.crt"] = "6969562e4080f424a1e7199f14baf3ee58ab6abb"
	fingerprints["https://pki.goog/gtsr1/GTSR1.crt"] = "e1c950e6ef22f84c5645728b922060d7d5a7a3e8"
	fingerprints["https://pki.goog/gtsr2/GTSR2.crt"] = "d273962a2a5e399f733fe1c71e643f033834fc4d"
	fingerprints["https://pki.goog/gtsr3/GTSR3.crt"] = "30d4246f07ffdb91898a0be9496611eb8c5e46e5"
	fingerprints["https://pki.goog/gtsr4/GTSR4.crt"] = "2a1d6027d94ab10a1c4d915ccd33a0cb3e2d54cb"

	mu := sync.Mutex{}
	wait := sync.WaitGroup{}
	wait.Add(len(fingerprints))

	all := make([]*x509.Certificate, 0)
	for u,chk := range fingerprints {
		go func(url, chk string) {
			cs := loadCerts(url)
			mu.Lock()
			defer mu.Unlock()
			defer wait.Done()

			if cs != nil {
				wh := []certs.WhitelistItem{
					certs.HexFingerprintWhitelistItem{Signature: chk},
				}
				kept := certs.Filter(cs, wh)
				if len(kept) > 0 {
					all = append(all, kept...)
				}
			}
		}(u, chk)
	}

	// todo: length check on certs

	wait.Wait()
	return all
}

func loadCerts(url string) []*x509.Certificate {
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	cert, err := certs.ParsePEMIntoCerts(b)
	if err != nil {
		return nil
	}

	return cert
}
