package tools

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

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

func ReadPemFileForTest(t *testing.T, path string) []*x509.Certificate {
	r, err := os.Open(path)
	defer r.Close()
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
