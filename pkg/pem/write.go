package pem

import (
	"bytes"
	"crypto/x509"
	p "encoding/pem"
	"io/ioutil"
	"os"
)

// ToFile overwrites file at `path` with the certificates encoded in
// PEM format.
func ToFile(path string, certs []*x509.Certificate) error {
	var perms os.FileMode = 0666
	stat, err := os.Stat(path)
	if err == nil {
		perms = stat.Mode()
	}

	// write the cert(s)
	var buf bytes.Buffer
	for i := range certs {
		b := &p.Block{
			Type:  "CERTIFICATE",
			Bytes: certs[i].Raw,
		}
		if err := p.Encode(&buf, b); err != nil {
			return err
		}
	}
	return ioutil.WriteFile(path, buf.Bytes(), perms)
}
