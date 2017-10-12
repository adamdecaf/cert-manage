// +build linux

package store

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/adamdecaf/cert-manage/tools/file"
	"github.com/adamdecaf/cert-manage/tools/pem"
)

type cadir struct {
	// base dir for all ca certs
	dir string
	// the filepath containing all certs (optional)
	all string
}

func (ca *cadir) empty() bool {
	if ca == nil {
		return false
	}
	path, err := filepath.Abs(ca.all)
	return err != nil || !file.Exists(path)
}

var (
	// From Go's source, src/crypto/x509/root_linux.go
	cadirs = []cadir{
		// Debian/Ubuntu/Gentoo/etc..
		cadir{
			dir: "/etc/ssl/certs",
			all: "/etc/ssl/certs/ca-certificates.crt",
		},
		// TODO(adam): These paths aren't supported, _yet_
		// "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
		// "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
		// "/etc/ssl/ca-bundle.pem",                            // OpenSUSE
		// "/etc/pki/tls/cacert.pem",                           // OpenELEC
	}
)

type linuxStore struct {
	ca cadir
}

func platform() Store {
	var ca cadir
	// find the cadir, if it exists
	for _, ca = range cadirs {
		if ca.empty() {
			break
		}
	}

	return linuxStore{
		ca: ca,
	}
}

func (s linuxStore) List() ([]*x509.Certificate, error) {
	if s.ca.empty() {
		return nil, nil
	}

	fmt.Printf("checking %s\n", s.ca.all)
	bytes, err := ioutil.ReadFile(s.ca.all)
	if err != nil {
		return nil, err
	}

	certs, err := pem.Parse(bytes)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// Remove walks through the installed CA certificates on a linux based
// machine and deactivates those that are not to be trusted.
//
// Steps
// 1. Walk through the dir (/etc/ssl/certs/) and chmod 000 the certs we aren't trusting
// 2. Run `update-ca-certificates` to re-create the ca-certificates.crt file
func (s linuxStore) Remove([]*x509.Certificate) error {
	return nil
}

// chmod 000 them
// - `restore` would be to `rwxrwxrwx` them...really?
// run update-ca-certificates
