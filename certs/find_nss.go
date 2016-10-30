package certs

import (
	"crypto/x509"
)

// Switch to NSS
// https://chromium.googlesource.com/chromium/src/+/master/docs/linux_cert_management.md
// https://wiki.mozilla.org/NSS_Shared_DB_And_LINUX

func FindCertsNSS() ([]*x509.Certificate, error) {
	return nil, nil
}
