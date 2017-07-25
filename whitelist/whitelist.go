package whitelist

import (
	"crypto/x509"
)

// TOOD(adam): Read and review this code
// https://blog.hboeck.de/archives/888-How-I-tricked-Symantec-with-a-Fake-Private-Key.html

// Item can be compared against an x509 Certificate to see if the cert represents
// some value presented by the whitelist item. This is useful in comparing specific fields of
// Certificate against multiple whitelist candidates.
type Item interface {
	Matches(x509.Certificate) bool
}

// Filter a list of x509 Certificates against whitelist items to
// retain only the certificates that are disallowed by our whitelist.
// An empty slice of certificates is a possible (and valid) output.
func Filter(incoming []*x509.Certificate, whitelisted []Item) []*x509.Certificate {
	// Pretty bad search right now.
	var removable []*x509.Certificate

	for _,inc := range incoming {
		remove := true
		// If the whitelist matches on something then don't remove it
		for _,wh := range whitelisted {
			if inc != nil && wh.Matches(*inc) {
				remove = false
			}
		}
		if remove {
			removable = append(removable, inc)
		}
	}

	return removable
}

// todo: dedup certs already added by one whitelist item
// e.g. If my []Item contains a signature and Issuer.CommonName match
// don't add the cert twice
