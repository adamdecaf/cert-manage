package fetch

import (
	"crypto/x509"
	"fmt"
	"github.com/adamdecaf/cert-manage/tools"
)

// PemCerts is a structure for pulling PEM encoded certs
type PemCerts struct {
	Fingerprints, Urls []string
}

// Pull will extract the certificates at from c.Urls and match them
// against known fingerprints to return a slice of certificates
func (c PemCerts) Pull() ([]*x509.Certificate, error) {
	bs := getRawDataFromUrls(c.Urls)

	cs := make([]*x509.Certificate, 0)
	for _, c := range bs {
		cert, err := tools.ParsePEMIntoCerts(c)
		if err != nil {
			return nil, fmt.Errorf("error parsing pem cert")
		}
		cs = append(cs, cert...)
	}

	if len(cs) != len(c.Fingerprints) {
		return nil, fmt.Errorf("pulled %d certs, but expected %d", len(cs), len(c.Fingerprints))
	}
	if len(c.Fingerprints) != len(c.Urls) {
		return nil, fmt.Errorf("%d expected fingerprints doesn't match %d expected urls", len(c.Fingerprints), len(c.Urls))
	}

	return filter(c.Fingerprints, cs), nil
}
