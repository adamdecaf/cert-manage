// +build darwin

package store

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/pem"
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
type darwinStore struct{}

func platform() Store {
	if debug {
		return darwinStore{}
	}
	return emptyStore{}
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

			err = pem.ToFile(where, certs[j:j+1]) // avoid creating a new slice
			if err != nil {
				return err
			}
		}
	}

	return nil
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
	trustItems, err := getCertsWithTrustPolicy()
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Printf("store/darwin: %d installed, %d with policy\n", len(installed), len(trustItems))
	}

	// If there's a trust policy verify it, otherwise don't bother.
	kept := make([]*x509.Certificate, 0)
	for i := range installed {
		// If we've got a policy only keep cert if it's still trusted
		if trustItems.contains(installed[i]) {
			trusted := certTrustedWithSystem(installed[i])
			if trusted {
				kept = append(kept, installed[i])
			}
			if debug {
				fmt.Printf("store/darwin: %s trust status after verify-cert: %v\n", certutil.GetHexSHA256Fingerprint(*installed[i]), trusted)
			}
			continue
		} else {
			// If there's no explicit policy assume it's trusted
			kept = append(kept, installed[i])
		}
	}
	return kept, nil
}

// certTrustedWithSystem calls out to `verify-cert` of the `security` cli tool
// to check if a certificate is still trusted, this comes about when a custom policy
// has been applied typically by the user.
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
	err = pem.ToFile(tmp.Name(), []*x509.Certificate{cert})
	if err != nil {
		if debug {
			fmt.Printf("store/darwin: error writing cert to tempfile, err=%v\n", err)
		}
		return false
	}

	cmd := exec.Command("/usr/bin/security", "verify-cert", "-L", "-l", "-c", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil && debug {
		fmt.Printf("Command ran: '%s'\n", strings.Join(cmd.Args, " "))
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
			fmt.Printf("Command ran: '%s'\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Output was: %s\n", string(out))
		}
		return nil, err
	}

	cs, err := pem.Parse(out)
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

// TODO(adam): Unlike Go, we don't really have a perf concern that pushes us towards
// grabbing this plist file and parsing it. We can shell out to `security verify-cert`
// and encur the time penality. It'll help us simplify the code.
//
// With our login.keychain modifications we'd need to verify against the login keychain
// overlayed with the system keychain anyway. (I'm not sure if this func does that now)
func getCertsWithTrustPolicy() (trustItems, error) {
	fd, err := trustSettingsExport()
	if err != nil {
		return nil, err
	}
	defer os.Remove(fd.Name())

	plist, err := parsePlist(fd)
	if err != nil {
		if err == io.EOF {
			if debug {
				fmt.Printf("store/darwin: EOF encountered with parsing trust-setting-export at: %s\n", fd.Name())
			}
			return plist.convertToTrustItems(), nil
		}
		return nil, err
	}

	return plist.convertToTrustItems(), nil
}

// trustSettingsExport calls out to the `security` cli tool and
// returns an os.File for the plist file written
//
// Note: Callers are expected to cleanup the file handler
func trustSettingsExport() (*os.File, error) {
	// Create temp file for plist output
	fd, err := ioutil.TempFile("", "trust-settings")
	if err != nil {
		return nil, fmt.Errorf("error creating trust-settings-export temp file: %v", err)
	}

	// build up command arguments
	args := append([]string{
		"trust-settings-export",
		"-d", fd.Name(),
	})

	// run command
	cmd := exec.Command("/usr/bin/security", args...)
	out, err := cmd.CombinedOutput()

	// The `security` cli will return an error if no trust settings were found. This seems to
	// be in the case when they keychain isn't setup (or a very fresh install, e.g. CI)
	if err != nil {
		if debug {
			fmt.Printf("Command ran: '%s'\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Output was: %s\n", string(out))
			fmt.Printf("Error: %s\n", err.Error())
		}
		// We are following what Go's source code does for building the x509.CertPool on darwin.
		// In that code all errors stemming from the `security` cli are ignored, but here we will
		// optionally log those (in debug) for analysis.
		return fd, nil
	}
	return fd, nil
}

func (s darwinStore) Remove(wh whitelist.Whitelist) error {
	certs, err := s.List()
	if err != nil {
		return err
	}

	loginKeychain, err := getLoginKeychain()
	if err != nil {
		return err
	}

	// remove := func(cert *x509.Certificate) error {
	// 	if cert == nil {
	// 		return errors.New("nil x509 certificate")
	// 	}

	// 	// Write the cert as a PEM block to a tempfile
	// 	tmp, err := ioutil.TempFile("", "cert-manage-remove-trusted-cert")
	// 	if err != nil {
	// 		return err
	// 	}
	// 	defer os.Remove(tmp.Name())

	// 	err = pem.ToFile(tmp.Name(), []*x509.Certificate{cert})
	// 	if err != nil {
	// 		return err
	// 	}

	// 	// After "System Integrity Protection" was added to macs not even root can modify files
	// 	// like /System/Library/Keychains/SystemRootCertificates.keychain
	// 	// SIP: https://support.apple.com/en-ca/HT204899
	// 	//
	// 	// Instead we apply a "Never Trust" override to the login keychain, which has the impact
	// 	// of not trusting that cert. This works nicely as undoing that work is as simple as
	// 	// deleting the "Never Trust" record in the login keychain
	// 	//
	// 	// https://superuser.com/questions/1070664/security-seckeychainitemdelete-unixoperation-not-permitted-on-os-x-when-tryi
	// 	// https://apple.stackexchange.com/questions/24640/how-do-i-remove-many-system-roots-from-apple-system-keychain

	// 	// TODO(adam): Changes
	// 	//  - Removed "sudo", from Command(..), works as expected on login keychain now
	// 	//  - Removed -d, works on login keychain now
	// 	// TODO(adam): Need to unlock keychain for a bit, typing password in everytime is crazy
	// 	cmd := exec.Command("/usr/bin/security", "add-trusted-cert", "-r", "deny", "-k", loginKeychain, tmp.Name())
	// 	out, err := cmd.CombinedOutput()
	// 	if debug {
	// 		fp := certutil.GetHexSHA256Fingerprint(*cert)
	// 		if err != nil {
	// 			output := string(out)

	// 			fmt.Printf("ERROR: during remove-trusted-cert (fingerprint=%s), error=%v\n", fp, err)
	// 			fmt.Printf("  Command ran: '%s'\n", strings.Join(cmd.Args, " "))
	// 			fmt.Printf("  Output was: %s\n", output)

	// 			if strings.Contains(output, "could not be found") {
	// 				if debug {
	// 					fmt.Println("Silencing error due to cert not found in keychain")
	// 				}
	// 				return nil
	// 			}

	// 		} else {
	// 			fmt.Printf("remove-trusted-cert (for %s)\n%s\n", fp, out)
	// 		}
	// 	}
	// 	return err
	// }

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
		// defer os.Remove(tmp.Name())

		// Write removable certs to temp file
		err = pem.ToFile(tmp.Name(), removable)
		if err != nil {
			return err
		}
		if debug {
			fmt.Printf("store/darwin: Wrote %d certs to %s\n", len(removable), tmp.Name())
		}

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

		// TODO(adam): Changes
		//  - Removed "sudo", from Command(..), works as expected on login keychain now
		//  - Removed -d, works on login keychain now
		// TODO(adam): Need to unlock keychain for a bit, typing password in everytime is crazy
		cmd := exec.Command("/usr/bin/security", "add-trusted-cert", "-r", "deny", "-k", loginKeychain, tmp.Name())
		out, err := cmd.CombinedOutput()
		if debug {
			if err != nil {
				output := string(out)
				fmt.Printf("ERROR: during removing darwin certs, error=%v\n", err)
				fmt.Printf("  Command ran: '%s'\n", strings.Join(cmd.Args, " "))
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
			certs, err := pem.FromFile(filepath.Join(dir, chainfds[i].Name(), certfiles[j].Name()))
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
					fmt.Printf("Command ran: '%s'\n", strings.Join(cmd.Args, " "))
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

// trustItems wraps up a collection of trustItems parsed from the `security` cli tool
type trustItems []trustItem

func (t trustItems) contains(cert *x509.Certificate) bool {
	if cert == nil {
		// we don't want to say we've got a nil cert
		return true
	}
	fp := certutil.GetHexSHA1Fingerprint(*cert)
	for i := range t {
		if fp == t[i].sha1Fingerprint {
			return true
		}
	}
	return false
}

var (
	// TODO(adam): Filter this down to just the SSL setting, by default
	dontTrustSettings = []byte(whitespaceReplacer.Replace(`<key>trustSettings</key><array>
<dict>
  <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
  <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAED</data>
  <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147408896</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAED</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEI</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147408872</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEI</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEJ</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEL</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEM</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEO</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEP</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEQ</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEU</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsPolicy</key><data>KoZIhvdjZAEC</data>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict>
<dict>
 <key>kSecTrustSettingsAllowedError</key><integer>-2147409654</integer>
 <key>kSecTrustSettingsResult</key><integer>3</integer>
</dict></array>`))
)

func (t trustItems) toXmlFile(where string) error {
	// Due to a known limitation of encoding/xml it often doesn't
	// follow the ordering of slices. To work around this we've decided
	// to build the xml in a more manual fashion.
	// https://golang.org/pkg/encoding/xml/#pkg-note-BUG

	// Write the header
	header := []byte(`<plist><dict><key>trustList</key><dict>`)
	itemEnd := []byte("</dict>")
	footer := []byte(`</dict>
  <key>trustVersion</key>
  <integer>1</integer>
</dict></plist>`)

	// Build up the inner contents
	out := make([]byte, 0)
	for i := 0; i < len(t); i += 1 {
		key := []byte(fmt.Sprintf("<key>%s</key>", strings.ToUpper(t[i].sha1Fingerprint)))

		// issuerName
		rdn := t[i].issuerName.ToRDNSequence()
		bs, _ := asn1.Marshal(rdn)
		issuer := []byte(fmt.Sprintf("<key>issuerName</key><data>%s</data>", base64.StdEncoding.EncodeToString(bs)))

		// modDate
		modDate := []byte(fmt.Sprintf("<key>modDate</key><date>%s</date>", t[i].modDate.Format(plistModDateFormat)))

		// serialNumber
		serial := []byte(fmt.Sprintf("<key>serialNumber</key><data>%s</data>", base64.StdEncoding.EncodeToString(t[i].serialNumber)))

		// Build item
		inner := append(key, []byte("<dict>")...)
		inner = append(inner, issuer...)
		inner = append(inner, modDate...)
		inner = append(inner, serial...)
		inner = append(inner, dontTrustSettings...)
		inner = append(inner, itemEnd...)

		// Ugh, join them all together
		out = append(out, inner...)
	}

	// write xml file out
	content := append(header, append(out, footer...)...)
	return ioutil.WriteFile(where, content, plistFilePerms)
}

// trustItem represents an entry from the plist (xml) files produced by
// the /usr/bin/security cli tool
type trustItem struct {
	// required
	sha1Fingerprint string
	issuerName      pkix.Name
	modDate         time.Time
	serialNumber    []byte

	// optional
	// TODO(adam): needs picked up?
	kSecTrustSettingsResult int32
}

func trustItemFromCertificate(cert x509.Certificate) trustItem {
	return trustItem{
		sha1Fingerprint: certutil.GetHexSHA1Fingerprint(cert),
		issuerName:      cert.Issuer,
		modDate:         time.Now(),
		serialNumber:    cert.SerialNumber.Bytes(),
	}
}

func (t trustItem) Serial() *big.Int {
	serial := big.NewInt(0)
	serial.SetBytes(t.serialNumber)
	return serial
}

func (t trustItem) String() string {
	modDate := t.modDate.Format(plistModDateFormat)

	name := fmt.Sprintf("O=%s", strings.Join(t.issuerName.Organization, " "))
	if t.issuerName.CommonName != "" {
		name = fmt.Sprintf("CN=%s", t.issuerName.CommonName)
	}

	country := strings.Join(t.issuerName.Country, " ")

	return fmt.Sprintf("SHA1 Fingerprint: %s\n %s (%s)\n modDate: %s\n serialNumber: %d", t.sha1Fingerprint, name, country, modDate, t.Serial())
}

func (t trustItem) equal(other trustItem) bool {
	return t.sha1Fingerprint == other.sha1Fingerprint
}

// parsePlist takes a reader of the xml output produced by trustSettingsExport()
// and converts it into a series of structs to then read
//
// After getting a `plist` callers will typically want to convert into
// a []trustItem by calling convertToTrustItems()
func parsePlist(in io.Reader) (plist, error) {
	dec := xml.NewDecoder(in)
	var out plist
	err := dec.Decode(&out)
	return out, err
}

// xml format, this was generated with the package github.com/gnewton/chidley
// but has also been modified by hand:
// 1. don't export struct names
// 2. remove outermost ChiChidleyRoot314159 wrapper as parsing fails with it
// 3. make `date []*date` rather than `date *date`
// 4. remove chi* from names as when we Marshal encoding/xml will use the struct's names
type plist struct {
	ChiDict *dict `xml:"dict,omitempty"`
}

type dict struct {
	ChiData    []*data    `xml:"data,omitempty"`
	ChiDate    []*date    `xml:"date,omitempty"`
	ChiDict    *dict      `xml:"dict,omitempty"`
	ChiInteger []*integer `xml:"integer,omitempty"`
	ChiKey     []*key     `xml:"key,omitempty"`
}

type key struct {
	Text string `xml:",chardata"`
}

type data struct {
	Text string `xml:",chardata"`
}

type date struct {
	Text string `xml:",chardata"`
}

type integer struct {
	Text bool `xml:",chardata"`
}

var (
	nonContentRegex    = regexp.MustCompile(`[^a-zA-Z0-9\+\/=]*`)
	whitespaceReplacer = strings.NewReplacer("\t", "", "\n", "", " ", "", "\r", "")
)

func (p *plist) convertToTrustItems() trustItems {
	out := make(trustItems, 0)

	if p.ChiDict == nil {
		return out
	}

	max := len(p.ChiDict.ChiDict.ChiDict.ChiData)
	for i := 0; i < max; i += 2 {
		item := trustItem{}

		item.sha1Fingerprint = strings.ToLower(p.ChiDict.ChiDict.ChiKey[i/2].Text)

		// trim whitespace
		s1 := whitespaceReplacer.Replace(nonContentRegex.ReplaceAllString(p.ChiDict.ChiDict.ChiDict.ChiData[i].Text, ""))
		s2 := whitespaceReplacer.Replace(nonContentRegex.ReplaceAllString(p.ChiDict.ChiDict.ChiDict.ChiData[i+1].Text, ""))

		bs1, _ := base64.StdEncoding.DecodeString(s1)
		bs2, _ := base64.StdEncoding.DecodeString(s2)

		// The issuerName's <data></data> block is only under asn1 encoding for the
		// issuerName field from 4.1.2.4 (https://tools.ietf.org/rfc/rfc5280)
		var issuer pkix.RDNSequence
		_, err := asn1.Unmarshal(bs1, &issuer)
		if err == nil {
			name := pkix.Name{}
			name.FillFromRDNSequence(&issuer)
			item.issuerName = name
		}

		dt := p.ChiDict.ChiDict.ChiDict.ChiDate[i/2].Text
		t, err := time.ParseInLocation(plistModDateFormat, dt, time.UTC)
		if err == nil {
			item.modDate = t
		}

		// serialNumber is just a base64 encoded big endian (big) int
		item.serialNumber = bs2

		out = append(out, item)
	}

	return out
}
