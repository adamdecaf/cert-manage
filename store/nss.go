package store

import (
	"crypto/x509"

	"github.com/adamdecaf/cert-manage/whitelist"
)

// Users of NSS
// Chrome: Linux
// Firefox: Darwin, Linux, Windows

// Docs:
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Tools/certutil
// - https://wiki.mozilla.org/NSS_Shared_DB
// - https://www.chromium.org/Home/chromium-security/root-ca-policy
//   - https://chromium.googlesource.com/chromium/src/+/master/docs/linux_cert_management.md
//   - https://wiki.mozilla.org/NSS_Shared_DB_And_LINUX

type nssStore struct{}

func NssStore() Store {
	return nssStore{}
}

func (s nssStore) Backup() error {
	return nil
}

// TODO(adam): this needs to accept an "nssType": firefox, thunderbird, etc
// which will let it figure out how better to list the contents from cert8.db
//
// TODO(adam): We'll need to discover the nss install (and bin/) location
// for whatever platform we're on.
//
// dir='/Users/adam/Library/Application Support/Firefox/Profiles/rrdlhe7o.default'
// $ /usr/local/opt/nss/bin/certutil -L -d "$dir" | grep banno
// banno_ca                                                     CT,C,C
//
// Listing certs
// $ /usr/local/opt/nss/bin/certutil -L -d "$dir"
//
// Certificate Nickname                                         Trust Attributes
//                                                              SSL,S/MIME,JAR/XPI
//
// USERTrust RSA Certification Authority                        ,,
// Microsoft IT SSL SHA2                                        ,,
// SSL.com High Assurance CA                                    ,,
// DigiCert SHA2 Extended Validation Server CA                  ,,
// Amazon Root CA 1                                             ,,
// ..
//
// Return one cert (PEM)
// /usr/local/opt/nss/bin/certutil -L -d "$dir" -n 'Microsoft IT SSL SHA2' -a
func (s nssStore) List() ([]*x509.Certificate, error) {
	return nil, nil
}

// TODO(adam): impl
// $ /usr/local/opt/nss/bin/certutil -M --help
// -M              Modify trust attributes of certificate
//    -n cert-name      The nickname of the cert to modify
//    -t trustargs      Set the certificate trust attributes (see -A above)
//    -d certdir        Cert database directory (default is ~/.netscape)
//    -P dbprefix       Cert & Key database prefix
func (s nssStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s nssStore) Restore(where string) error {
	return nil
}
