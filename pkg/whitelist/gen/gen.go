package gen

import (
	"crypto/x509"
	"net/url"
)

func FindCACertificates([]*url.URL) ([]*x509.Certificate, error) {
	return nil, nil
}

type gate struct {
	c chan struct{}
}
func (g gate) begin() {
	g.c <- struct{}{}
}
func (g gate) done() {
	select {
	case <-g.c:
	default:
		panic("invalid state")
	}
}
func newgate(n int) *gate {
	return &gate{
		c: make(chan struct{}, n),
	}
}

