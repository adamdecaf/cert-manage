package certs

import (
	"crypto/x509"
)

// ``
func Keep(incoming []*x509.Certificate, whitelisted []WhitelistItem) []*x509.Certificate {
	// Pretty bad search right now.
	var keep []*x509.Certificate
	for _,inc := range incoming {
		for _,wh := range whitelisted {
			if inc != nil && wh.Matches(*inc) {
				keep = append(keep, inc)
			}
		}
	}
	return keep
}
