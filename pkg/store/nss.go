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

package store

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

var (
	cutil = crtutil{
		execPaths: []string{
			"/usr/local/opt/nss/bin/certutil", // Darwin
			"/usr/bin/crtutil",                // Linux
		},
	}

	// certutil trust attrubutes
	// Run `crtutil -A -H` for the full list
	trustAttrsProhibited = "p,p,p"
	trustAttrsTrusted    = "CT,C,C"
)

type nssStore struct {
	// nssType refers to the application using this NSS instance
	// This is used for printing back to the user and for backup/restore.
	nssType string

	// appVersion refers to the version of whatever tool is using NSS
	appVersion string

	// foundCertdbLocation is the locally found filepath to a cert.db file
	foundCertdbLocation string

	// Holds a trigger if we've made modifications (useful for triggering a "Restart app" message
	// after we're done with modifications.
	notify *sync.Once
}

// NssStore returns an implementation of Store for NSS certificate stores
//
// Docs:
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/An_overview_of_NSS_Internals
// - https://wiki.mozilla.org/NSS_Shared_DB
// - https://wiki.mozilla.org/NSS_Shared_DB_And_LINUX
func NssStore(nssType string, appVersion string, certdbPath string) Store {
	return nssStore{
		nssType:             nssType,
		appVersion:          appVersion,
		foundCertdbLocation: certdbPath,
		notify:              &sync.Once{},
	}
}

// Checks if a cert8.db or cert9.db file exists at the given path
func containsCertdb(where string) bool {
	if fd, err := os.Stat(where); err != nil || !fd.IsDir() {
		return false // ignore non-directories
	}
	if fd, err := os.Stat(filepath.Join(where, "cert9.db")); !os.IsNotExist(err) {
		return fd.Size() > 0
	}
	if fd, err := os.Stat(filepath.Join(where, "cert8.db")); !os.IsNotExist(err) {
		return fd.Size() > 0
	}
	return false
}

// NSS apps sometimes require being restarted to get the updated set of trustAttrs for each certificate
// TOOD(adam): I think this is only true for cert8.db installs...
func (s nssStore) notifyToRestart() {
	s.notify.Do(func() {
		fmt.Printf("Restart %s to refresh certificate trust\n", strings.Title(s.nssType))
	})
}

func (s nssStore) Add(certs []*x509.Certificate) error {
	dir, err := ioutil.TempDir("", "cert-manage-nss-add")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// write each cert out to a file and then add it
	for i := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		path := filepath.Join(dir, fmt.Sprintf("%s.pem", fp))

		err = certutil.ToFile(path, certs[i:i+1])
		if err != nil {
			return err
		}

		nick := strings.Replace(certutil.StringifyPKIXName(certs[i].Subject), " ", "_", -1)
		err = cutil.addCertificate(s.foundCertdbLocation, path, nick)
		if err != nil {
			return err
		}
	}

	if len(certs) > 0 {
		s.notifyToRestart()
	}

	return nil
}

func (s nssStore) Backup() error {
	dir, err := getCertManageDir(s.nssType)
	if err != nil {
		return err
	}

	// Only backup the first nss cert.db path for now
	if s.foundCertdbLocation == "" {
		return errors.New("No NSS cert db paths found")
	}

	// Copy file into backup location
	src := filepath.Join(s.foundCertdbLocation, filepath.Base(s.foundCertdbLocation))
	dst := filepath.Join(dir, fmt.Sprintf("cert.db-%d", time.Now().Unix()))
	return file.CopyFile(src, dst)
}

func (s nssStore) GetLatestBackup() (string, error) {
	dir, err := getCertManageDir(s.nssType)
	if err != nil {
		return "", fmt.Errorf("GetLatestBackup: error getting %s backup directory err=%v", s.nssType, err)
	}
	return getLatestBackup(dir)
}

func (s nssStore) GetInfo() *Info {
	return &Info{
		Name:    strings.Title(s.nssType),
		Version: s.appVersion,
	}
}

// List returns the installed (and trusted) certificates contained in a NSS cert.db file
//
// To list certificates with the NSS `crtutil` tool the following would be ran
// $ /usr/local/opt/nss/bin/crtutil -L -d "$dir"
//
// Note: `dir` represents a directory path which contains a cert.db file
func (s nssStore) List(opts *ListOptions) ([]*x509.Certificate, error) {
	if s.foundCertdbLocation == "" {
		return nil, errors.New("unable to find NSS db directory")
	}

	items, err := cutil.listCertsFromDB(s.foundCertdbLocation, opts)
	if err != nil {
		return nil, err
	}

	kept := make([]*x509.Certificate, 0)
	for i := range items {
		// TODO(adam): Check for opts.Expired or opts.Revoked
		if opts.Trusted && items[i].trustedForSSL() {
			kept = append(kept, items[i].certs...)
		}
		if opts.Untrusted {
			kept = append(kept, items[i].certs...)
		}
	}
	return kept, nil
}

func (s nssStore) Remove(wh whitelist.Whitelist) error {
	if s.foundCertdbLocation == "" {
		return errors.New("unable to find NSS db directory")
	}

	items, err := cutil.listCertsFromDB(s.foundCertdbLocation, &ListOptions{
		Trusted:   true,
		Untrusted: true,
	})
	if err != nil {
		return err
	}

	// Remove trust from each cert if needed.
	for i := range items {
		if wh.MatchesAll(items[i].certs) {
			continue
		}

		// whitelist didn't match, blacklist cert
		defer s.notifyToRestart()
		err = cutil.modifyTrustAttributes(s.foundCertdbLocation, items[i].nick, trustAttrsProhibited)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s nssStore) Restore(where string) error {
	src, err := s.GetLatestBackup()
	if err != nil {
		return err
	}

	// Find filename from src (latest backup)
	fname := "cert9.db"
	if _, err := os.Stat(filepath.Join(src, "cert8.db")); !os.IsNotExist(err) {
		fname = "cert8.db"
	}

	// Queue notification to restart app
	defer s.notifyToRestart()

	// Restore the latest backup file
	return file.CopyFile(src, filepath.Join(s.foundCertdbLocation, fname))
}

// certdbItem represents an x509 Certificate with the NSS trust attributes
type certdbItem struct {
	nick  string
	certs []*x509.Certificate

	// The 'Trust Attributes' header from `crtutil -L`, this represents three usecases for
	// x509 Certificates: SSL,S/MIME,JAR/XPI
	trustAttrs string
}

func (c certdbItem) trustedForSSL() bool {
	// We only care about the first C,.,. attribute, which is for SSL
	parts := strings.SplitN(c.trustAttrs, ",", 2)
	if len(parts) != 2 {
		if debug {
			fmt.Printf("store/nss: after trustAttrs split (in %d parts): %s\n", len(parts), parts)
		}
		return false
	}

	// The only attribute for explicit distrust is 'p', which per the docs:
	//  p 	 prohibited (explicitly distrusted)
	//
	// The other flags refer to sending warnings (but still trusted), user certs,
	// or other attributes which may limit, but not explicitly remove trust
	// in regards to SSL/TLS communication.
	return !strings.Contains(parts[0], "p")
}

// crtutil represents the NSS cli tool by the same name
// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Tools/crtutil
type crtutil struct {
	execPaths []string
}

func (c crtutil) getExecPath() (string, error) {
	for i := range c.execPaths {
		if file.IsExecutable(c.execPaths[i]) {
			return c.execPaths[i], nil
		}
	}
	return "", errors.New("No executable for NSS `crtutil` found")
}

// Different versions of NSS/cert.db files require different prefixes
// when passed to crtutil.
func (c crtutil) appendScheme(where string) string {
	if filepath.Base(where) == "cert9.db" {
		return "sql:" + where
	}
	return "dbm:" + where
}

// Emulates the following
// /usr/local/opt/nss/bin/certutil -A -a -n <nick> -t 'CT,C,C' -i cert.pem -d <dir>
func (c crtutil) addCertificate(dir string, where string, nick string) error {
	expath, err := c.getExecPath()
	if err != nil {
		return err
	}
	args := []string{
		"-A", "-a",
		"-n", nick,
		"-t", trustAttrsTrusted,
		"-i", where,
		"-d", c.appendScheme(dir),
	}
	cmd := exec.Command(expath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if debug {
			fmt.Printf("Command was:\n %s\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Output was: %q\n", string(out))
		}
		return err
	}
	return nil
}

// Emulates the following
// /usr/local/opt/nss/bin/crtutil -L -d '~/Library/Application Support/Firefox/Profiles/rrdlhe7o.default'
func (c crtutil) listCertsFromDB(path string, opts *ListOptions) ([]certdbItem, error) {
	expath, err := c.getExecPath()
	if err != nil {
		return nil, err
	}

	args := []string{
		"-L",
		"-d", c.appendScheme(path),
	}
	cmd := exec.Command(expath, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was:\n %s\n", strings.Join(cmd.Args, " "))
		}
		return nil, err
	}

	// parse out each 'Certificate Nickname' field
	// there are some header lines that are either whitespace or contain the following:
	//
	// Certificate Nickname                                         Trust Attributes
	// SSL,S/MIME,JAR/XPI
	//
	items := make([]certdbItem, 0)
	for {
		// read next line
		line, err := stdout.ReadString(byte('\n'))
		if err != nil && err != io.EOF {
			return nil, err
		}

		// convert the line into a certdbItem
		nick, trust := c.parseCertdbItem(line)
		if nick == "" || trust == "" {
			if err == io.EOF {
				break
			}
			continue // skip blank lines (headers are returned here as blank)
		}
		certs, err := c.readCertificatesForNick(path, nick)
		if err != nil {
			return nil, err
		}

		items = append(items, certdbItem{
			nick:       nick,
			certs:      certs,
			trustAttrs: trust,
		})

		// quit if we hit the end
		if err == io.EOF {
			break
		}
	}

	return items, nil
}

func (c crtutil) parseCertdbItem(line string) (nick string, trust string) {
	line = strings.TrimSpace(line)

	if len(line) == 0 ||
		strings.Contains(line, "Certificate Nickname") ||
		strings.Contains(line, "SSL,S/MIME,JAR/XPI") {
		return
	}

	// Pull out the 'Certificate Nickname'
	// Examples:
	// DigiCert SHA2 Extended Validation Server CA                  ,,
	// Symantec Class 3 Extended Validation SHA256 SSL CA           CT,C,C
	split := strings.Split(line, " ")

	nick = strings.TrimSpace(strings.Join(split[:len(split)-1], " "))
	trust = strings.TrimSpace(split[len(split)-1:][0]) // last

	return
}

// Emulates
//
// /usr/local/opt/nss/bin/crtutil -L -d "$dir" -n 'Microsoft IT SSL SHA2' -a
func (c crtutil) readCertificatesForNick(path string, nick string) ([]*x509.Certificate, error) {
	expath, err := c.getExecPath()
	if err != nil {
		return nil, err
	}

	args := []string{
		"-L",
		"-a",
		"-d", c.appendScheme(path),
		"-n", nick,
	}
	cmd := exec.Command(expath, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was:\n %s\n", strings.Join(cmd.Args, " "))
		}
		return nil, err
	}

	certs, err := certutil.ParsePEM(stdout.Bytes())
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// Emulates
//
// $ /usr/local/opt/nss/bin/crtutil -M -n <nick> -t <trust-args> -d <dir>
func (c crtutil) modifyTrustAttributes(path string, nick, trustAttrs string) error {
	expath, err := c.getExecPath()
	if err != nil {
		return err
	}

	args := []string{
		"-M",
		"-n", nick,
		"-t", trustAttrs,
		"-d", c.appendScheme(path),
	}
	cmd := exec.Command(expath, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	if debug {
		fmt.Printf("Command was: \n%s\nOutput was: \n%s\n", strings.Join(cmd.Args, " "), stdout.String())
	}
	return err
}
