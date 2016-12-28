package certs

import (
	"crypto/x509"
)

// ``
func Keep(incoming []*x509.Certificate, whitelisted []WhitelistItem) []*x509.Certificate {
	return nil
}
