package ca

import (
	"crypto/x509"
	"github.com/adamdecaf/cert-manage/fetch"
)

func Visa() ([]*x509.Certificate, error) {
	cs := fetch.PemCerts{
		Fingerprints: []string{
			"fac9bd55fb0ac78d53bbee5cf1d597989fd0aaab20a25151bdf1733ee7d122",
		},
		Urls: []string{
			"http://enroll.visaca.com/VisaCAeCommerceRoot.crt",
		},
	}
	return cs.Pull()
}
