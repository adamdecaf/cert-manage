package main

import (
	"crypto/x509"
)

const (
	SponsoredTrustedRootsUrl = "https://pki.goog/roots.pem"
)

// This is a list of roots suggested by Google as certs to trust.
// It's pulled from https://pki.goog/roots.pem
func GoogleSuggestedRoots() []*x509.Certificate {
	cs := pemCerts{
		urls: []string{
			SponsoredTrustedRootsUrl,
		},
	}
	return cs.Pull()
}

// Returns the Google owned CA certs
// These are copied from https://pki.goog/
func Google() []*x509.Certificate {
	cs := pemCerts{
		fingerprints: []string {
			"https://pki.goog/gsr2/GSR2.crt",
			"https://pki.goog/gsr4/GSR4.crt",
			"https://pki.goog/gtsr1/GTSR1.crt",
			"https://pki.goog/gtsr2/GTSR2.crt",
			"https://pki.goog/gtsr3/GTSR3.crt",
			"https://pki.goog/gtsr4/GTSR4.crt",
		},
		urls: []string{
			"75e0abb6138512271c04f85fddde38e4b7242efe",
			"6969562e4080f424a1e7199f14baf3ee58ab6abb",
			"e1c950e6ef22f84c5645728b922060d7d5a7a3e8",
			"d273962a2a5e399f733fe1c71e643f033834fc4d",
			"30d4246f07ffdb91898a0be9496611eb8c5e46e5",
			"2a1d6027d94ab10a1c4d915ccd33a0cb3e2d54cb",
		},
	}
	return cs.Pull()
}
