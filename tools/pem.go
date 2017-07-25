package tools

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

// ParsePEMIntoCerts will extract the slice of certificates encoded in PEM format
func ParsePEMIntoCerts(blob []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *pem.Block
	for {
		block, blob = pem.Decode(blob)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("unable to find certs in PEM blob")
	}
	return certs, nil
}

// ReadPemFileForTest will read and parse a PEM encoded file of certificates.
// This function intentionally disregards errors as it is only intended to be
// used in tests.
func ReadPemFileForTest(t *testing.T, path string) []*x509.Certificate {
	r, err := os.Open(path)
	defer func() {
		e := r.Close()
		if e != nil {
			fmt.Printf("error closing test pem file - %s\n", e)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}

	body, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	certificates, err := ParsePEMIntoCerts(body)
	if err != nil {
		t.Fatal(err)
	}
	return certificates
}
