// +build darwin

package store

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/adamdecaf/cert-manage/tools/_x509"
	"github.com/adamdecaf/cert-manage/tools/pem"
	"github.com/adamdecaf/cert-manage/whitelist"
)

// Docs
// - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html
// - https://github.com/adamdecaf/cert-manage/issues/9#issuecomment-337778241

var (
	plistModDateFormat = "2006-01-02T15:04:05Z"
	systemDirs         = []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}

	// internal options
	debug = strings.Contains(os.Getenv("GODEBUG"), "x509roots=1")
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

// TODO(adam): impl
// - Capture `trust-settings-export` to another file
func (s darwinStore) Backup() error {
	return nil
}

// List
//
// Note: Currently we are ignoring the login keychain. This is done because those certs are
// typically modified by the user (or an application the user trusts).
func (s darwinStore) List() ([]*x509.Certificate, error) {
	installed, err := readInstalledCerts(systemDirs...)
	if err != nil {
		return nil, err
	}
	trustItems, err := getCertsWithTrustPolicy()
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Printf("%d installed, %d with policy\n", len(installed), len(trustItems))
	}

	kept := make([]*x509.Certificate, 0)
	for i := range installed {
		if installed[i] == nil {
			continue
		}
		if trustItems.contains(installed[i]) {
			kept = append(kept, installed[i])
			continue
		}
	}

	return kept, nil
}

func readInstalledCerts(paths ...string) ([]*x509.Certificate, error) {
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

func getCertsWithTrustPolicy() (trustItems, error) {
	fd, err := trustSettingsExport()
	defer os.Remove(fd.Name())
	if err != nil {
		return nil, err
	}

	plist, err := parsePlist(fd)
	if err != nil {
		return nil, err
	}

	return plist.convertToTrustItems(), nil
}

// returns an os.File for the plist file written
// Note: Callers are expected to cleanup the file handler
func trustSettingsExport(args ...string) (*os.File, error) {
	// Create temp file for plist output
	fd, err := ioutil.TempFile("", "trust-settings")
	if err != nil {
		return nil, err
	}

	// build up args
	args = append([]string{
		"trust-settings-export", "-s", fd.Name(),
	}, args...)

	// run command
	_, err = exec.Command("/usr/bin/security", args...).Output()
	if err != nil {
		return nil, err
	}

	return fd, nil
}

// TODO(adam): impl
// /usr/bin/security trust-settings-export
// - Can this shell out and let the OS prompt? Otherwise we'd need to print out the command
func (s darwinStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

// TODO(adam): impl
func (s darwinStore) Restore() error {
	// /usr/bin/security trust-settings-import
	// ^ will prompt users, so I think the 'Restore' should just be
	// outputting what command to run and telling users to run it
	return nil
}

type trustItems []trustItem

func (t trustItems) contains(cert *x509.Certificate) bool {
	if cert == nil {
		// we don't want to say we've got a nil cert
		return true
	}
	fp := _x509.GetHexSHA1Fingerprint(*cert)
	for i := range t {
		if fp == t[i].sha1Fingerprint {
			return true
		}
	}
	return false
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
	kSecTrustSettingsResult int32
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
