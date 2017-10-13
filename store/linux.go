// +build linux

package store

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/adamdecaf/cert-manage/tools/_x509"
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
func (s linuxStore) Remove(removable []*x509.Certificate) error {
	// Check each CA cert file and optionally disable
	walk := func(path string, info os.FileInfo, err error) error {
		// Ignore SkipDir and directories
		if (err != nil && err != filepath.SkipDir) || info.IsDir() {
			return nil
		}

		// TODO(adam): ignore backup files, or those w/ info.Mode == 000

		// read the cert(s) contained at the file and only keep those
		// that aren't removable
		read, err := pem.FromFile(path)
		if err != nil {
			return err
		}
		// TODO(adam): This is pretty similar to _just_ another round of
		// whitelist calls...
		for i := 0; i < len(read); i++ {
			for k := range removable {
				// fmt.Printf("i=%d, len(read)=%d, k=%d, len(removable)=%d\n", i, len(read), k, len(removable))
				if read[i] == nil || removable[k] == nil {
					return fmt.Errorf("either read[i]='%v' or removable[k]='%v' is nil", read[i], removable[k])
				}

				// match, so remove
				if _x509.GetHexSHA256Fingerprint(*read[i]) == _x509.GetHexSHA256Fingerprint(*removable[k]) {
					// remove cert from `read`
					read = append(read[:i], read[i+1:]...)
					if len(read) == 0 {
						break
					}
				}
			}
		}

		// // chmod 000 the file if it's going to be empty
		// if len(read) == 0 {
		// 	// disable the file
		// 	// fmt.Println("A")
		// 	return os.Remove(path, 0000)
		// }

		// otherwise, write kept certs from `read` back
		err = pem.ToFile(path, read)
		if err != nil {
			return err
		}

		return nil
	}

	// Walk the fs and deactivate each cert
	err := filepath.Walk(s.ca.dir, walk)
	if err != nil {
		return err
	}

	// Update the certs trust system-wide
	var out bytes.Buffer
	cmd := exec.Command("/usr/sbin/update-ca-certificates")
	cmd.Stdout = &out

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("error updating trust status: err=%v, out=%s", err, out.String())
	}

	return nil
}

// TOOD(adam): `restore` would be to `rwxrwxrwx` them...really?
// actually, use `dpkg-reconfigure ca-certificates`
