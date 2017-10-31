package store

import (
	"crypto/x509"

	"github.com/adamdecaf/cert-manage/whitelist"
)

// Docs:
// - https://chromium.googlesource.com/chromium/src/+/master/docs/linux_cert_management.md
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
// - https://wiki.mozilla.org/NSS_Shared_DB_And_LINUX
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/tools/NSS_Tools_certutil#Listing_Certificates_in_a_Database

const (
	nssPublicURL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"
)

type nssStore struct{}

func NssStore() Store {
	return nssStore{}
}

func (s nssStore) Backup() error {
	return nil
}

func (s nssStore) List() ([]*x509.Certificate, error) {
	return nil, nil
}

// TODO(adam): impl
func (s nssStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s nssStore) Restore(where string) error {
	return nil
}
