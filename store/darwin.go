// +build darwin

package store

import (
	"crypto/x509"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"

	"github.com/adamdecaf/cert-manage/tools/pem"
	"github.com/adamdecaf/cert-manage/whitelist"
)

// Docs
// - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html

var (
	systemDirs = []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}
)

func getUserDirs() ([]string, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	return []string{
		filepath.Join(u.HomeDir, "/Library/Keychains/login.keychain"),
		filepath.Join(u.HomeDir, "/Library/Keychains/login.keychain-db"),
	}, nil
}

type darwinStore struct{}

func platform() Store {
	return darwinStore{}
}

func (s darwinStore) Backup() error {
	return nil
}

// List
//
// Note: Currently we are ignoring the login keychain. This is done because those certs are
// typically modified by the user (or an application the user trusts).
func (s darwinStore) List() ([]*x509.Certificate, error) {
	return readDarwinCerts(systemDirs...)
}

func readDarwinCerts(paths ...string) ([]*x509.Certificate, error) {
	// key: fingerprint
	res := make([]*x509.Certificate, 0)

	args := []string{"find-certificate", "-a", "-p"}
	args = append(args, paths...)

	b, err := exec.Command("/usr/bin/security", args...).Output()
	if err != nil {
		return nil, err
	}

	cs, err := pem.Parse(b)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c == nil {
			continue
		}
		add := true
		for i := range res {
			if reflect.DeepEqual(c.Signature, res[i].Signature) {
				add = false
				break
			}
		}
		if add {
			res = append(res, c)
		}
	}

	return res, nil
}

// TODO(adam): impl
func (s darwinStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s darwinStore) Restore() error {
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
