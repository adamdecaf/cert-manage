package certutil

import (
	"bytes"
	"crypto/x509"

	"github.com/adamdecaf/extract-nss-root-certs"
)

type decoder func([]byte) ([]*x509.Certificate, error)

var (
	decoders = []decoder{
		ParsePEM,
		readNSSCerts,
	}
)

// Decode attempts to read `bs` with a few different parsers
// to return an array of x509 Certificates
func Decode(bs []byte) ([]*x509.Certificate, error) {
	for i := range decoders {
		certs, err := decoders[i](bs)
		if err == nil && len(certs) > 0 {
			return certs, nil
		}
	}
	return nil, nil
}

func readNSSCerts(bs []byte) ([]*x509.Certificate, error) {
	cfg := nsscerts.Config{}
	r := bytes.NewReader(bs)
	return nsscerts.List(r, &cfg)
}
