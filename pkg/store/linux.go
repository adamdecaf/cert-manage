// Copyright 2018 Adam Shannon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
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
	"strings"
	"time"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

type cadir struct {
	// directory for new/custom certificates
	add string

	// base dir for all ca certs
	dir string

	// the filepath containing all certs (optional)
	all string

	// reload/refresh command
	refresh string
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
			add:     "/usr/local/share/ca-certificates",
			dir:     "/usr/share/ca-certificates",
			all:     "/etc/ssl/certs/ca-certificates.crt",
			refresh: "/usr/sbin/update-ca-certificates",
		},
	}

	linuxBackupDir = "linux"
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

func (s linuxStore) Add(certs []*x509.Certificate) error {
	if s.ca.empty() {
		return errors.New("unable to find certificate directory")
	}

	// install each certificate
	for i := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		path := filepath.Join(s.ca.add, fmt.Sprintf("%s.crt", fp))

		err := certutil.ToFile(path, certs[i:i+1])
		if err != nil {
			return err
		}
	}

	if len(certs) > 0 {
		return s.rebundleCerts()
	}
	return nil
}

// Backup takes a snapshot of the current set of CA certificates and
// saves them to another location. It will overwrite any previous backup.
func (s linuxStore) Backup() error {
	dir, err := getCertManageDir(fmt.Sprintf("%s/%d", linuxBackupDir, time.Now().Unix()))
	if err != nil {
		return err
	}
	return file.MirrorDir(s.ca.dir, dir)
}

func (s linuxStore) GetLatestBackup() (string, error) {
	dir, err := getCertManageDir(linuxBackupDir)
	if err != nil {
		return "", fmt.Errorf("GetLatestBackup: error getting linux backup directory, err=%v", err)
	}
	return getLatestBackup(dir)
}

func (s linuxStore) uname(args ...string) string {
	out, err := exec.Command("uname", args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (s linuxStore) GetInfo() *Info {
	return &Info{
		Name:    s.uname("-o"), // GNU/Linux,
		Version: s.uname("-r"), // 4.9.60-linuxkit-aufs
	}
}

// List returns the x509 Certificates trusted on a Linux system
//
// Note: Linux does not offer support for "untrusting" a certificate
// it must be removed instead.
func (s linuxStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	if s.ca.empty() {
		return nil, nil
	}

	bytes, err := ioutil.ReadFile(s.ca.all)
	if err != nil {
		return nil, err
	}

	// TODO(adam): Filter out expired and revoked certs, based on ListOptions
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

	return s.rebundleCerts()
}

func (s linuxStore) Restore(where string) error {
	dir, err := s.GetLatestBackup()
	if err != nil {
		return err
	}
	if debug {
		fmt.Printf("store/linux: restoring from backup dir %s\n", dir)
	}

	// Remove the current dir
	if file.Exists(s.ca.dir) {
		err := os.RemoveAll(s.ca.dir)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// Restore
	err = file.MirrorDir(dir, s.ca.dir)
	if err != nil {
		return err
	}
	return s.rebundleCerts()
}

// Update the certs trust system-wide
func (s linuxStore) rebundleCerts() error {
	var out bytes.Buffer

	cmd := exec.Command("sudo", s.ca.refresh)
	if os.Getuid() == 0 {
		// drop sudo if we're already root
		cmd = exec.Command(s.ca.refresh)
	}
	cmd.Stdout = &out

	if debug {
		fmt.Println("store/linux: updated CA certificates")
	}

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error updating trust status: err=%v, out=%s", err, out.String())
	}
	return nil
}
