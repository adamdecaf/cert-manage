package certs

import (
	"crypto/x509"
)

// Docs:
// - https://chromium.googlesource.com/chromium/src/+/master/docs/linux_cert_management.md
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
// - https://wiki.mozilla.org/NSS_Shared_DB_And_LINUX

func FindCertsNSS() ([]*x509.Certificate, error) {
	return nil, nil
}
