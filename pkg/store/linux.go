// +build linux

package store

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

type cadir struct {
	// base dir for all ca certs
	dir string

	// the filepath containing all certs (optional)
	all string

	// where to save a backup of all certs
	backup string
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
		{
			dir:    "/usr/share/ca-certificates",
			all:    "/etc/ssl/certs/ca-certificates.crt",
			backup: "/usr/share/ca-certificates.backup",
		},
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

// Backup takes a snapshot of the current set of CA certificates and
// saves them to another location. It will overwrite any previous backup.
func (s linuxStore) Backup() error {
	return file.MirrorDir(s.ca.dir, s.ca.backup)
}

func (s linuxStore) List() ([]*x509.Certificate, error) {
	if s.ca.empty() {
		return nil, nil
	}

	bytes, err := ioutil.ReadFile(s.ca.all)
	if err != nil {
		return nil, err
	}

	certs, err := certutil.ParsePEM(bytes)
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
func (s linuxStore) Remove(wh whitelist.Whitelist) error {
	// Check each CA cert file and optionally disable
	walk := func(path string, info os.FileInfo, err error) error {
		// Ignore SkipDir and directories
		if (err != nil && err != filepath.SkipDir) || info.IsDir() {
			return nil
		}

		// read the cert(s) contained at the file and only keep those
		// that aren't removable
		read, err := certutil.FromFile(path)
		if err != nil {
			return err
		}
		for i := 0; i < len(read); i++ {
			// Remove the cert if we don't match
			if !wh.Matches(read[i]) {
				read = append(read[:i], read[i+1:]...)
				if len(read) == 0 {
					break
				}
			}
		}

		// otherwise, write kept certs from `read` back
		err = certutil.ToFile(path, read)
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

	return bundleCerts()
}

func (s linuxStore) Restore(where string) error {
	if !file.Exists(s.ca.backup) {
		return errors.New("No backup directory exists")
	}
	// Remove the current dir
	if file.Exists(s.ca.dir) {
		err := os.RemoveAll(s.ca.dir)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// Restore
	err := file.MirrorDir(s.ca.backup, s.ca.dir)
	if err != nil {
		return err
	}
	return bundleCerts()
}

// Update the certs trust system-wide
func bundleCerts() error {
	var out bytes.Buffer
	cmd := exec.Command("/usr/sbin/update-ca-certificates")
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error updating trust status: err=%v, out=%s", err, out.String())
	}
	return nil
}
