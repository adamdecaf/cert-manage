package certutil

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

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

	certificates, err := ParsePEM(body)
	if err != nil {
		return nil, fmt.Errorf("error parsing certs, err=%v", err)
	}
	return certificates, nil
}
