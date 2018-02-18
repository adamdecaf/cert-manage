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

	// systemRootCertificates is the bundled set of CA's from Apple.
	//
	// After "System Integrity Protection" was added to macs not even root can modify files
	// like /System/Library/Keychains/SystemRootCertificates.keychain, because many (all?) files
	// under /System are write/modify protected. There is some super-hacky way to reboot and disable
	// that, but we'd never go down that route.
	//
	// SIP: https://support.apple.com/en-ca/HT204899
	// https://superuser.com/questions/1070664/security-seckeychainitemdelete-unixoperation-not-permitted-on-os-x-when-tryi
	systemRootCertificates = "/System/Library/Keychains/SystemRootCertificates.keychain"

	// systemKeychain is the device wide keychain. If a login keychain doesn't specify an override then the trust
	// is pulled from here. We're free to modify this with sudo
	systemKeychain = "/Library/Keychains/System.keychain"

	// loginKeychain represents the default location for the user's 'login.keychain', which
	// is typically where overrides (e.g. corporate CA's) are installed into.
	loginKeychain = filepath.Join(file.HomeDir(), "/Library/Keychains/login.keychain")

	// TODO(adam): What's ~/Library/Keychains/login.keychain-db
	// Oh, it's the filepath from older osx versions

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
type darwinStore struct{}

func platform() Store {
	return darwinStore{}
}

func (s darwinStore) Add(certs []*x509.Certificate) error {
	dir, err := ioutil.TempDir("", "cert-manage-add")
	if err != nil {
		return fmt.Errorf("Add: error creating temp dir err=%v", err)
	}
	defer os.RemoveAll(dir)

	for i := range certs {
		// Write each cert to its own file and then add it
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		path := filepath.Join(dir, fmt.Sprintf("%s.pem", fp))
		err := certutil.ToFile(path, certs[i:i+1])
		if err != nil {
			return fmt.Errorf("Add: error writing cert %s to tempfile %s, err=%v", certs[i].Subject, path, err)
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
		return fmt.Errorf("Backup: error getting cert-manage dir, err=%v", err)
	}

	// Backup the certificates from the login keychain and export each into a separate file
	// The backup format looks like this: darwin/$time/$keychain-name/$fingerprint.crt
	// Files are PEM encoded x509 certificates.
	if _, err := os.Stat(loginKeychain); os.IsNotExist(err) {
		if debug {
			fmt.Printf("store/darwin: Backup: skipping login keychain as it's missing")
		}
		return nil
	}

	_, fname := filepath.Split(loginKeychain)
	certs, err := readInstalledCerts(loginKeychain)
	if err != nil {
		return fmt.Errorf("Backup: error reading installed certs from %s, err=%v", loginKeychain, err)
	}
	dir, err := getCertManageDir(filepath.Join(parent, fname))
	if err != nil {
		return fmt.Errorf("Backup: error getting cert-manage dir, err=%v", err)
	}

	// Write each certificate to the underlying fs
	for i := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		where := filepath.Join(dir, fmt.Sprintf("%s.crt", fp))

		err = certutil.ToFile(where, certs[i:i+1]) // avoid creating a new slice
		if err != nil {
			return fmt.Errorf("Backup: error writing cert %s to temp file %s, err=%v", certs[i].Subject, where, err)
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
	// Grab certs from all keychains which are readable
	installed, err := readInstalledCerts(systemRootCertificates, systemKeychain, loginKeychain)
	if err != nil {
		return nil, err
	}

	// If there's a trust policy verify it, otherwise don't bother.
	kept := make([]*x509.Certificate, 0)
	for i := range installed {
		// Unlike Go, we don't really have a performance concern that pushes us towards grabbing a
		// plist file from 'security' and parsing it. We can shell out to 'security verify-cert'
		// and encur the time penality.
		trusted := certTrustedWithSystem(installed[i])
		if trusted {
			// TODO(adam): dedup?
			kept = append(kept, installed[i])
		}
		if debug {
			fmt.Printf("store/darwin: %s trust status after verify-cert: %v\n", certutil.GetHexSHA256Fingerprint(*installed[i]), trusted)
		}
	}
	return kept, nil
}

// certTrustedWithSystem calls out to `verify-cert` of the `security` cli tool to check
// if a certificate is still trusted, this comes about when a custom policy has been
// applied typically by the user or System.
func certTrustedWithSystem(cert *x509.Certificate) bool {
	if cert == nil {
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

	// We don't specify -k systemKeychain to use the default search path, it's what apps would do.
	cmd := exec.Command("/usr/bin/security", "verify-cert", "-p", "ssl", "-c", tmp.Name())
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

// Remove works to mark certificates not whitelisted as 'Never Trust' in the System keychain.
// This effectively disables the certificate unless the user's login keychain has overrides.
func (s darwinStore) Remove(wh whitelist.Whitelist) error {
	// We just want to read the system roots and remove trust in those not whitelisted
	roots, err := readInstalledCerts(systemRootCertificates)
	if err != nil {
		return fmt.Errorf("Remove: error reading certs from %s, err=%v", systemRootCertificates, err)
	}

	// prep a temp file we can re-use
	tmp, err := ioutil.TempFile("", "cert-manage-darwin-remove")
	if err != nil {
		return fmt.Errorf("Remove: error creating temp dir, err=%v", err)
	}
	defer os.Remove(tmp.Name())

	for i := range roots {
		if !wh.Matches(roots[i]) {
			// Root CA isn't part of our whitelist, so we need to remove trust for
			// it in the system keychain
			err = certutil.ToFile(tmp.Name(), roots[i:i+1]) // avoid new slice
			if err != nil {
				return fmt.Errorf("error writing to temp file %s, err=%v", tmp.Name(), err)
			}

			// mark the certificate as 'Never Trust' in the system keychain
			// e.g. sudo security add-trusted-cert -d -r deny -p ssl -k /Library/Keychains/System.keychain aaa.pem
			cmd := exec.Command("sudo", "/usr/bin/security", "add-trusted-cert", "-d", "-r", "deny", "-p", "ssl", "-k", systemKeychain, tmp.Name())
			out, err := cmd.CombinedOutput()
			if err != nil {
				if debug {
					output := string(out)
					fmt.Printf("ERROR: during removing darwin certs, error=%v\n", err)
					fmt.Printf("  Command ran: %q\n", strings.Join(cmd.Args, " "))
					fmt.Printf("  Output was: %s\n", output)
				}
				return fmt.Errorf("error marking cert %s as 'Never Trust' in system keychain, err=%v", roots[i].Subject, err)
			}
		}
	}

	return nil
}

// Restore operates mostly on the system keychain and removes certificates which we've
// explicitly marked "Never Trust". This re-enables them for use by apps.
//
// Afterwords, the login keychain is restored from its most recent backup.
//
// TODO(adam): `where` needs to be a directory with properly exported certs from keychain files
func (s darwinStore) Restore(where string) error {
	// Grab apple provided system root, this is our baseline
	roots, err := readInstalledCerts(systemRootCertificates)
	if err != nil {
		return fmt.Errorf("Restore: error reading certs from %s, err=%v", systemRootCertificates, err)
	}

	// temp file for certs
	tmp, err := ioutil.TempFile("", "restore-verify-cert")
	if err != nil {
		return fmt.Errorf("Restore: error creating temp dir, err=%v", err)
	}
	defer os.Remove(tmp.Name())

	for i := range roots {
		err = certutil.ToFile(tmp.Name(), roots[i:i+1])
		if err != nil {
			return fmt.Errorf("Restore: error writing cert %s to temp dir %s, err=%v", roots[i].Subject, tmp.Name(), err)
		}

		cmd := exec.Command("security", "verify-cert", "-p", "ssl", "-k", systemKeychain, "-c", tmp.Name())
		out, err := cmd.CombinedOutput()
		outStr := string(out)
		if err != nil {
			if strings.Contains(outStr, "kSecTrustResultDeny") {
				// Cert is actually untrusted, so let's restore trust and remove it from the System keychain

				// sudo security add-trusted-cert -d -r unspecified -k /Library/Keychains/System.keychain aaa.pem
				cmd = exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "unspecified", "-k", systemKeychain, tmp.Name())
				// TODO(adam): attach stdout/stderr
				if err = cmd.Run(); err != nil {
					return fmt.Errorf("Remove: error removing 'Never Trust' from cert %s, err=%v", roots[i].Subject, err)
				}

				// sudo security delete-certificate -Z D1EB23A46D17D68FD92564C2F1F1601764D8E349 /Library/Keychains/System.keychain
				fp := certutil.GetHexSHA1Fingerprint(*roots[i])
				cmd = exec.Command("sudo", "security", "delete-certificate", "-Z", fp, systemKeychain)
				if err = cmd.Run(); err != nil {
					// TODO(adam): ignore 'not found' errors (whatever I removed before)
					return fmt.Errorf("Remove: error deleting cert %s from keychain, err=%v", roots[i].Subject, err)
				}
			} else if strings.Contains(outStr, "CSSMERR_TP_CERT_EXPIRED") {
				continue
			} else if strings.Contains(outStr, "Invalid Extended Key Usage") {
				continue
			} else {
				fmt.Println(outStr)
				return fmt.Errorf("Remove: ran into other error with verify-cert for %s, err=%v", roots[i].Subject, err)
			}
		}
	}

	// No idea why, but there are some Apple certificates which don't get whitelisted.
	// For now, let's force them to be fixed up

	// CN=Apple Root CA
	// B0B1730ECBC7FF4505142C49F1295E6EDA6BCAED7E2C68C5BE91B5A11001F024
	// CN=Apple Root CA - G2
	// C2B9B042DD57830E7D117DAC55AC8AE19407D38E41D88F3215BC3A890444A050
	// CN=Apple Root CA - G3
	// 63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179
	// CN=Apple Root Certificate Authority
	// 0D83B611B648A1A75EB8558400795375CAD92E264ED8E9D7A757C1F5EE2BB22D

	// Restore the login.keychain
	//
	// Grab the filenames under our backup directory (e.g. login.keychain/$sha1.crt), read the cert
	// and verify it's matching the sha1 filename and compare against the already installed certs.
	dir, err := getCertManageDir(darwinBackupDir)
	if err != nil {
		return fmt.Errorf("Restore: error reading backup dir, err=%v", err)
	}
	dir, err = getLatestBackup(dir)
	if err != nil {
		return fmt.Errorf("Restore: error getting latest backup, err=%v", err)
	}
	dir = filepath.Join(dir, "login.keychain")
	if debug {
		fmt.Printf("store/darwin: Found backup dir at %s\n", dir)
	}

	alreadyInstalled, err := readInstalledCerts(loginKeychain)
	if err != nil {
		return fmt.Errorf("Restore: error getting login keychain certs, err=%v", err)
	}
	var alreadyInstalledFingerprints []string
	for i := range alreadyInstalled {
		alreadyInstalledFingerprints = append(alreadyInstalledFingerprints, certutil.GetHexSHA256Fingerprint(*alreadyInstalled[i]))
	}

	// read each file from our backup
	certfiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("Restore: error reading backup dir contents, err=%v", err)
	}
	for i := range certfiles {
		// For each cert file, grab the certs and find the one that matches the filename hash
		_, fp := filepath.Split(certfiles[i].Name())
		certs, err := certutil.FromFile(filepath.Join(dir, certfiles[i].Name()))
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("Restore: error reading certs from %s, err=%v", certfiles[i].Name(), err)
		}
		if len(certs) == 0 {
			if debug {
				fmt.Printf("store/darwin: no certificates found in backup file: %s\n", certfiles[i].Name())
			}
			continue
		}
		// find cert whose fingerprint matches filename
		for j := range certs {
			if fp == certutil.GetHexSHA256Fingerprint(*certs[j]) { // found cert, now add if it's not already in keychian
				shouldAdd := true
				for k := range alreadyInstalledFingerprints {
					if fp == alreadyInstalledFingerprints[k] {
						shouldAdd = false
					}
				}
				if shouldAdd {
					err = s.Add(certs[j : j+1])
					if err != nil {
						return fmt.Errorf("Restore: error adding cert %s to login keychain, err=%v", certs[j].Subject, err)
					}
				}
			}
		}
	}

	return nil
}
