package pem

import (
	"crypto/x509"
	p "encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/adamdecaf/cert-manage/tools/file"
)

// Parse will extract the slice of certificates encoded in PEM format
func Parse(blob []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *p.Block
	for {
		block, blob = p.Decode(blob)
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
	return certs, nil
}

// FromFile reads a series of PEM encoded blocks from the given file
func FromFile(path string) ([]*x509.Certificate, error) {
	if !file.Exists(path) {
		return nil, fmt.Errorf("%s does not exist", path)
	}

	r, err := os.Open(path)
	defer func() {
		e := r.Close()
		if e != nil {
			fmt.Printf("error closing test pem file - %s\n", e)
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("error opening file, err=%v", err)
	}

	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error reading file, err=%v", err)
	}

	certificates, err := Parse(body)
	if err != nil {
		return nil, fmt.Errorf("error parsing certs, err=%v", err)
	}
	return certificates, nil
}
