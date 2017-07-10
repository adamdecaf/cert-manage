package fetch

import (
	"crypto/x509"
	"fmt"

	"github.com/adamdecaf/cert-manage/tools"
)

// Pull PEM encoded certs
type pemCerts struct {
	fingerprints, urls []string
}
func (c pemCerts) Pull() ([]*x509.Certificate, error) {
	bs := load(c.urls)

	cs := make([]*x509.Certificate, 0)
	for _, c := range bs {
		cert, err := tools.ParsePEMIntoCerts(c)
		if err != nil {
			return nil, fmt.Errorf("error parsing pem cert")
		}
		cs = append(cs, cert...)
	}

	if len(cs) != len(c.fingerprints) {
		return nil, fmt.Errorf("pulled %d certs, but expected %d", len(cs), len(c.fingerprints))
	}
	if len(c.fingerprints) != len(c.urls) {
		return nil, fmt.Errorf("%d expected fingerprints doesn't match %d expected urls", len(c.fingerprints), len(c.urls))
	}

	return filter(c.fingerprints, cs), nil
}

// TODO(adam): fixup that we're using load(), filter() and readRemoteData() from der.go
