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

// +build darwin

package store

import (
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

var (
	plistModDateFormat = "2006-01-02T15:04:05Z"
	systemKeychains    = []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}
	// Folder under ~/Library/cert-manage/ to put backups
	darwinBackupDir = "darwin"
)

const (
	plistFilePerms = 0644
)

// Docs
// https://www.apple.com/certificateauthority/ca_program.html

// darwinStore represents the structure of a `store.Store`, but for the darwin (OSX and
// macOS) platform.
//
// Within the code a cli tool called `security` is often used to extract and modify the
// trust settings of installed certificates in the various Keychains.
//
// https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html
type darwinStore struct {
	// holds `emptyStore{}` to reject unfinished methods
	empty Store
}

func platform() Store {
	return darwinStore{
		empty: emptyStore{},
	}
}

func (s darwinStore) Add(certs []*x509.Certificate) error {
	loginKeychain, err := getLoginKeychain()
	if err != nil {
		return err
	}

	dir, err := ioutil.TempDir("", "cert-manage-add")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	for i := range certs {
		// Write each cert to its own file and then add it
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		path := filepath.Join(dir, fmt.Sprintf("%s.pem", fp))
		err := certutil.ToFile(path, certs[i:i+1])
		if err != nil {
			return err
		}

		// add cert to keychain
		cmd := exec.Command("security", "add-trusted-cert", "-r", "trustRoot", "-k", loginKeychain, path)
		out, err := cmd.CombinedOutput()
		if err != nil && debug {
			fmt.Printf("Command ran: %q\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Output was: %s\n", string(out))
		}
	}
	return nil
}

func (s darwinStore) Backup() error {
	// setup (and create) backup (parent) dir
	parent, err := getCertManageDir(fmt.Sprintf("%s/%d", darwinBackupDir, time.Now().Unix()))
	if err != nil {
		return err
	}

	keychainFilepaths, err := getKeychainPaths(systemKeychains)
	if err != nil {
		return err
	}

	// Take each keychain and export each certificate into a separate file (costly.. I know)
	// this way we can restore them much easier.
	//
	// The backup format looks like this: darwin/$time/$keychain-name/$fingerprint.crt
	// Files are PEM encoded x509 certificates.
	for i := range keychainFilepaths {
		if _, err := os.Stat(keychainFilepaths[i]); os.IsNotExist(err) {
			if debug {
				fmt.Printf("store/darwin: skipping %s because it does not exist\n", keychainFilepaths[i])
			}
			continue
		}

		// Backup the certs from each keychain file
		_, fname := filepath.Split(keychainFilepaths[i])
		certs, err := readInstalledCerts(keychainFilepaths[i])
		if err != nil {
			return err
		}
		dir, err := getCertManageDir(filepath.Join(parent, fname))
		if err != nil {
			return err
		}

		// Write each certificate to the underlying fs
		for j := range certs {
			fp := certutil.GetHexSHA256Fingerprint(*certs[j])
			where := filepath.Join(dir, fmt.Sprintf("%s.crt", fp))

			err = certutil.ToFile(where, certs[j:j+1]) // avoid creating a new slice
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s darwinStore) GetInfo() *Info {
	return &Info{
		Name:    "Darwin (OSX)",
		Version: s.version(),
	}
}

// Show OS version
// From: https://superuser.com/questions/75166/how-to-find-out-mac-os-x-version-from-terminal
func (s darwinStore) version() string {
	out, err := exec.Command("sw_vers", "-productVersion").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (s darwinStore) List() ([]*x509.Certificate, error) {
	chains, err := getKeychainPaths(systemKeychains)
	if err != nil {
		return nil, err
	}
	installed, err := readInstalledCerts(chains...)
	if err != nil {
		return nil, err
	}

	// If there's a trust policy verify it, otherwise don't bother.
	kept := make([]*x509.Certificate, 0)
	for i := range installed {
		// Unlike Go, we don't really have a performance concern that pushes us towards grabbing a
		// plist file from 'security' and parsing it. We can shell out to 'security verify-cert'
		// and encur the time penality.
		//
		// With our login.keychain modifications we'd need to verify against the login keychain
		// overlayed with the system keychain anyway, which certTrustedWithLoginKeychain does.
		trusted := certTrustedWithLoginKeychain(installed[i])
		if trusted {
			kept = append(kept, installed[i])
		}
		if debug {
			fmt.Printf("store/darwin: %s trust status after verify-cert: %v\n", certutil.GetHexSHA256Fingerprint(*installed[i]), trusted)
		}
	}
	return kept, nil
}

// certTrustedWithLoginKeychain calls out to `verify-cert` of the `security` cli tool
// to check if a certificate is still trusted, this comes about when a custom policy
// has been applied typically by the user.
func certTrustedWithLoginKeychain(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	loginKeychain, err := getLoginKeychain()
	if err != nil {
		return false
	}

	tmp, err := ioutil.TempFile("", "verify-cert")
	if err != nil {
		if debug {
			fmt.Printf("store/darwin: error creating temp file for verify-cert: err=%v\n", err)
		}
		return false
	}
	defer os.Remove(tmp.Name())

	// write pem block somewhere and shell out
	err = certutil.ToFile(tmp.Name(), []*x509.Certificate{cert})
	if err != nil {
		if debug {
			fmt.Printf("store/darwin: error writing cert to tempfile, err=%v\n", err)
		}
		return false
	}

	cmd := exec.Command("/usr/bin/security", "verify-cert", "-L", "-l", "-k", loginKeychain, "-c", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil && debug {
		fmt.Printf("Command ran: %q\n", strings.Join(cmd.Args, " "))
		fmt.Printf("Output was: %s\n", string(out))
	}
	return err == nil
}

// readInstalledCerts pulls certificates from the `security` cli tool that's
// installed. This will return certificates, but not their trust status.
func readInstalledCerts(paths ...string) ([]*x509.Certificate, error) {
	res := make([]*x509.Certificate, 0)

	args := []string{"find-certificate", "-a", "-p"}
	args = append(args, paths...)

	cmd := exec.Command("/usr/bin/security", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if debug {
			fmt.Printf("Command ran: %q\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Output was: %s\n", string(out))
		}
		return nil, err
	}

	cs, err := certutil.ParsePEM(out)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c == nil {
			continue
		}
		add := true
		sig := certutil.GetHexSHA256Fingerprint(*c)
		for i := range res {
			if res[i] == nil {
				continue
			}
			if sig == certutil.GetHexSHA256Fingerprint(*res[i]) {
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

func (s darwinStore) Remove(wh whitelist.Whitelist) error {
	if !debug {
		return s.empty.Remove(wh)
	}

	certs, err := s.List()
	if err != nil {
		return err
	}

	loginKeychain, err := getLoginKeychain()
	if err != nil {
		return err
	}

	// TODO(adam): useful docs?
	// After "System Integrity Protection" was added to macs not even root can modify files
	// like /System/Library/Keychains/SystemRootCertificates.keychain
	// SIP: https://support.apple.com/en-ca/HT204899
	//
	// Instead we apply a "Never Trust" override to the login keychain, which has the impact
	// of not trusting that cert. This works nicely as undoing that work is as simple as
	// deleting the "Never Trust" record in the login keychain
	//
	// https://superuser.com/questions/1070664/security-seckeychainitemdelete-unixoperation-not-permitted-on-os-x-when-tryi
	// https://apple.stackexchange.com/questions/24640/how-do-i-remove-many-system-roots-from-apple-system-keychain

	// Remove certificates that are not whitelisted
	removable := make([]*x509.Certificate, 0)
	for i := range certs {
		if !wh.Matches(certs[i]) {
			// collect certs that we are going to remove trust for and later
			// apply one `security` cli command, otherwise users are prompted
			// on each command
			fmt.Printf("Subject=%v\n", certs[i].Subject)
			removable = append(removable, certs[i])
		}
	}

	if len(removable) > 0 {
		// Write removable certs to a file and run `security` to remove trust
		tmp, err := ioutil.TempFile("", "cert-manage-Remove")
		if err != nil {
			return err
		}
		// defer os.Remove(tmp.Name()) // TODO(adam): keep?

		// Write removable certs to temp file
		err = certutil.ToFile(tmp.Name(), removable)
		if err != nil {
			return err
		}
		if debug {
			fmt.Printf("store/darwin: Wrote %d certs to %s\n", len(removable), tmp.Name())
		}

		// TODO(adam): Changes
		//  - Removed "sudo", from Command(..), works as expected on login keychain now
		//  - Removed -d, works on login keychain now
		// TODO(adam): Need to unlock keychain for a bit, typing password in everytime is crazy
		// TODO(adam): Detect if password is enabled on keychain, and if so abort or confirm go forward?
		cmd := exec.Command("/usr/bin/security", "add-trusted-cert", "-r", "deny", "-k", loginKeychain, tmp.Name())
		out, err := cmd.CombinedOutput()
		if debug {
			if err != nil {
				output := string(out)
				fmt.Printf("ERROR: during removing darwin certs, error=%v\n", err)
				fmt.Printf("  Command ran: %q\n", strings.Join(cmd.Args, " "))
				fmt.Printf("  Output was: %s\n", output)

				if strings.Contains(output, "could not be found") {
					if debug {
						fmt.Println("Silencing error due to cert not found in keychain")
					}
					return nil
				}
			}
			if debug {
				fmt.Printf("store/darwin: Removed %d certificates\n", len(removable))
			}
		}
		return err
	}

	return nil
}

// TODO(adam): `where` needs to be a directory with properly exported certs from keychain files
//
// TODO(adam): Restore Steps
//  1. Remove any certs from a "system keychain" that are marked as "Never Trust" in the login keychain
//  2. Add any certs in the login.keychain backup to login.keychain
//     - Should we do this? Is that expected? -- Yes, we're restoring from the latest backup.
//
// TODO(adam): Do we need to backup anything but the "login keychain" and "SystemRootCertificates" keychain?
func (s darwinStore) Restore(where string) error {
	if !debug {
		return s.empty.Restore(where)
	}

	// Find latest backup dir
	dir, err := getCertManageDir(darwinBackupDir)
	if err != nil {
		return err
	}
	dir, err = getLatestBackup(dir)
	if err != nil {
		return err
	}
	if debug {
		fmt.Printf("store/darwin: Found backup dir at %s\n", dir)
	}

	// Grab each folder at `dir`, which represents the keychain name
	chainfds, err := ioutil.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("ERROR: Failed to read %s as dir, err=%v", dir, err)
	}
	loginKeyChain, err := getLoginKeychain()
	if err != nil {
		return err
	}

	// Cycle over folders (and nested files) found in the backup dir to restore
	// the login keychain (by removing overrides which alter trust status).
	for i := range chainfds {
		// Grab the filenames under chainfds[i] (e.g. System.keychain/$sha1.crt), read the cert
		// and verify it's matching the sha1 filename. Remove the cert from the login keychain
		// if it's marked as 'Never Trust' to the user.
		//
		// TODO(adam): Don't do anything if the cert is already in the chain. (via readInstalledCerts)
		certfiles, err := ioutil.ReadDir(filepath.Join(dir, chainfds[i].Name()))
		if err != nil {
			return err
		}

		for j := range certfiles {
			certs, err := certutil.FromFile(filepath.Join(dir, chainfds[i].Name(), certfiles[j].Name()))
			if err != nil {
				return err
			}
			if len(certs) == 0 {
				return fmt.Errorf("no certificates found in backup file: %s", certfiles[j].Name())
			}

			// Remove cert from the login keychain
			//
			// TODO(adam): Actually find the cert, don't assume it's [0]
			// TODO(adam): IDEA: Don't delete cert if it's only found in login.keychain (e.g. banno_ca)
			//             This is sorta counter to whitelist though..
			//
			// sudo security delete-certificate -t -Z DE28F4A4FFE5B92FA3C503D1A349A7F9962A8212 ~/Library/Keychains/login.keychain
			fp := certutil.GetHexSHA1Fingerprint(*certs[0])
			cmd := exec.Command("/usr/bin/security", "delete-certificate", "-t", "-Z", fp, loginKeyChain)
			out, err := cmd.CombinedOutput()
			if err != nil {
				if debug {
					fmt.Printf("Command ran: %q\n", strings.Join(cmd.Args, " "))
					fmt.Printf("Output was: %s\n", string(out))
				}
				if strings.Contains(string(out), "Unable to delete certificate matching") {
					if debug {
						fmt.Printf("store/darwin: Ignoring removal failure of %s because it doesn't exist in %s\n", fp, loginKeyChain)
					}
					continue
				}
				return err
			}
		}
	}

	return nil
}

func getKeychainPaths(initial []string) ([]string, error) {
	uhome := file.HomeDir()
	if uhome == "" {
		return nil, errors.New("unable to find user's home dir")
	}

	return append(initial,
		filepath.Join(uhome, "/Library/Keychains/login.keychain"),
		filepath.Join(uhome, "/Library/Keychains/login.keychain-db"),
	), nil
}

func getLoginKeychain() (string, error) {
	needles, err := getKeychainPaths(nil)
	if err != nil {
		return "", err
	}
	for i := range needles {
		_, err := os.Stat(needles[i])
		if err != nil {
			if !os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		return needles[i], nil
	}
	return "", errors.New("no login keychain found")
}
