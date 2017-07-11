package fetch

import (
	"crypto/x509"
	"fmt"
)

// Pull ASN.1 DER encoded certificates
type DerCerts struct {
	Fingerprints, Urls []string
}
func (c DerCerts) Pull() ([]*x509.Certificate, error) {
	bs := getRawDataFromUrls(c.Urls)

	cs := make([]*x509.Certificate, 0)
	for _, c := range bs {
		cert, err := x509.ParseCertificates(c)
		if err != nil {
			return nil, fmt.Errorf("error parsing der cert")
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
