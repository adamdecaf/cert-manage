// +build darwin

package store

import (
	"crypto/x509"
	"os/exec"

	"github.com/adamdecaf/cert-manage/tools/pem"
)

// Docs
// - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html

type darwinStore struct{}

func platform() Store {
	return darwinStore{}
}

func (s darwinStore) List() ([]*x509.Certificate, error) {
	b, err := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p").Output()
	if err != nil {
		return nil, err
	}

	certs, err := pem.Parse(b)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// TODO(adam): impl
func (s darwinStore) Remove([]*x509.Certificate) error {
	return nil
}

// TODO(adam): find and show each cert's trust status

// // security remove-trusted-cert <crt-file>
// // exit code 1 and stderr of:
// //  'SecTrustSettingsRemoveTrustSettings: The specified item could not be found in the keychain.'
// // if the cert isn't in the keychain
// //
// // otherwise, it will open an alert box for the password
// // is there a way to batch up removals?
// //
// // or, how does that work when go is exec'ing out?

// // security add-trusted-cert <crt-file>
// // works.

// // Is there a way to disable a cert? aka mark it as "Never Trust"?
// // Otherwise, we'll need to make a full backup of all certs before touching anything.
// // ^ Then offer a way to mass-import all of them.
