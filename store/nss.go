package store

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/adamdecaf/cert-manage/tools/file"
	"github.com/adamdecaf/cert-manage/tools/pem"
	"github.com/adamdecaf/cert-manage/whitelist"
)

// Docs:
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Tools/certutil
// - https://wiki.mozilla.org/NSS_Shared_DB
// - https://www.chromium.org/Home/chromium-security/root-ca-policy
//   - https://chromium.googlesource.com/chromium/src/+/master/docs/linux_cert_management.md
//   - https://wiki.mozilla.org/NSS_Shared_DB_And_LINUX

var (
	cutil = certutil{
		execPaths: []string{
			"/usr/local/opt/nss/bin/certutil", // Darwin
			"/usr/bin/certutil",               // Linux
		},
	}

	// We're only going to support the current version (cert8.db)
	// https://wiki.mozilla.org/NSS_Shared_DB#Where_we_are_today
	cert8Filename = "cert8.db"

	// Trust Attributes which signify "No Trust"
	// Run `certutil -A -H` for the full list
	trustAttrsNoTrust = "p,p,p"
)

type nssStore struct {
	// nssType refers to the application using this nss cert8.db instance
	// often multiple applications can share one db, or there are multiple
	// cert8.db files on a system.
	// This allows backups and restores to operate on the correct cert8.db file
	// for a given application.
	nssType string

	// cert8dbSuggestedDirs represent the fs locations where cert8.db are stored
	// In the case of an app like Firefox this would be looking in the following locations:
	//  ~/Library/Application Support/Firefox/Profiles/*  (Darwin)
	cert8dbSuggestedDirs []cert8db

	// foundCert8dbLocation is a shortcut for a locally found cert8.db file
	// The expected result is a directory that can be passed into certutil's -d option
	foundCert8dbLocation cert8db

	// Holds a trigger if we've made modifications (useful for triggering a "Restart app" message
	// after we're done with modifications.
	notify *sync.Once
}

func NssStore(nssType string, suggestedDirs []cert8db, foundCert8db cert8db) nssStore {
	return nssStore{
		nssType:              nssType,
		cert8dbSuggestedDirs: suggestedDirs,
		foundCert8dbLocation: foundCert8db,
		notify:               &sync.Once{},
	}
}

func locateCert8db(suggestions []cert8db) cert8db {
	if debug {
		if len(suggestions) == 0 {
			fmt.Println("store/nss: no cert8.db paths suggested")
			return cert8db("")
		}
		fmt.Printf("store/nss: suggestions: ")
		for i := range suggestions {
			fmt.Printf("%s, ", string(suggestions[i]))
		}
		fmt.Printf("\n")
	}

	for i := range suggestions {
		// Glob and find a cert8.db file
		matches, err := filepath.Glob(string(suggestions[i]))
		if err != nil {
			if debug {
				fmt.Printf("store/nss: %v\n", err)
			}
			return cert8db("")
		}

		// Accumulate dirs with a cert8.db file
		for j := range matches {
			if containsCert8db(matches[j]) {
				return cert8db(matches[j])
			}
		}
	}

	return cert8db("")
}

func containsCert8db(p string) bool {
	where := filepath.Join(p, cert8Filename)
	if debug {
		fmt.Printf("store/nss: guessing cert8.db location: %s\n", where)
	}
	s, err := os.Stat(where)
	if err != nil {
		return false
	}
	return s.Size() > 0
}

// NSS apps often require being restarted to get the updated set of trustAttrs for each certificate
func (s nssStore) notifyToRestart() {
	s.notify.Do(func() {
		fmt.Printf("Restart %s to refresh certificate trust\n", strings.Title(s.nssType))
	})
	return
}

// we should be able to backup a cert8.db file directly
func (s nssStore) Backup() error {
	dir, err := getCertManageDir(s.nssType)
	if err != nil {
		return err
	}

	// Only backup the first nss cert8.db path for now
	if s.foundCert8dbLocation.empty() {
		return errors.New("No NSS cert db paths found")
	}

	// Copy file into backup location
	src := filepath.Join(string(s.foundCert8dbLocation), cert8Filename)
	dst := filepath.Join(dir, fmt.Sprintf("cert8.db-%d", time.Now().Unix()))
	return file.CopyFile(src, dst)
}

// List returns the installed (and trusted) certificates contained in a NSS cert8.db file
//
// To list certificates with the NSS `certutil` tool the following would be ran
// $ /usr/local/opt/nss/bin/certutil -L -d "$dir"
//
// Note: `dir` represents a directory path which contains a cert8.db file
func (s nssStore) List() ([]*x509.Certificate, error) {
	if s.foundCert8dbLocation.empty() {
		return nil, errors.New("unable to find NSS db directory")
	}

	items, err := cutil.listCertsFromDB(s.foundCert8dbLocation)
	if err != nil {
		return nil, err
	}

	kept := make([]*x509.Certificate, 0)
	for i := range items {
		if items[i].trustedForSSL() {
			kept = append(kept, items[i].certs...)
		}
	}
	return kept, nil
}

func (s nssStore) Remove(wh whitelist.Whitelist) error {
	if s.foundCert8dbLocation.empty() {
		return errors.New("unable to find NSS db directory")
	}

	items, err := cutil.listCertsFromDB(s.foundCert8dbLocation)
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
		err = cutil.modifyTrustAttributes(s.foundCert8dbLocation, items[i].nick, trustAttrsNoTrust)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s nssStore) Restore(where string) error {
	dir, err := getCertManageDir(s.nssType)
	if err != nil {
		return err
	}
	src, err := getLatestBackup(dir)
	if err != nil {
		return err
	}

	// Try and find a dir that eixsts, which could hold a cert8.db file
	var dst string
	for i := range s.cert8dbSuggestedDirs {
		matches, err := filepath.Glob(string(s.cert8dbSuggestedDirs[i]))
		if err != nil {
			return err
		}

		for j := range matches {
			if st, err := os.Stat(matches[j]); err == nil && st.IsDir() {
				dst = matches[j]
				break
			}
		}
		if dst != "" {
			break
		}
	}
	if dst == "" {
		return fmt.Errorf("No directory found to restore %s certificates", s.nssType)
	}

	// Queue notification to restart app
	defer s.notifyToRestart()

	// Restore the latest backup file
	dst = filepath.Join(dst, cert8Filename)
	return file.CopyFile(src, dst)
}

// cert8db represents a fs path for a cert8.db file
type cert8db string

func (c cert8db) empty() bool {
	return len(string(c)) == 0
}

// cert8Item represents an x509 Certificate with the NSS trust attributes
type cert8Item struct {
	nick  string
	certs []*x509.Certificate

	// The 'Trust Attributes' header from `certutil -L`, this represents three usecases for
	// x509 Certificates: SSL,S/MIME,JAR/XPI
	trustAttrs string
}

func (c cert8Item) trustedForSSL() bool {
	parts := strings.SplitN(c.trustAttrs, ",", 2) // We only care about the first C,.,. attribute
	if len(parts) != 2 {
		if debug {
			fmt.Printf("store/nss: after trustAttrs split (in %d parts): %s\n", len(parts), parts)
		}
		return false
	}

	// The only attribute for explicit distrust is 'p', which per the docs:
	// 'p 	 prohibited (explicitly distrusted)'
	//
	// The other flags refer to sending warnings (but still trusted), user certs,
	// or other attributes which may limit, but not explicitly remove trust
	// in regards to SSL/TLS communication.
	return !strings.Contains(parts[0], "p")
}

// certutil represents the NSS cli tool by the same name
type certutil struct {
	execPaths []string
}

func (c certutil) getExecPath() (string, error) {
	for i := range c.execPaths {
		if file.IsExecutable(c.execPaths[i]) {
			return c.execPaths[i], nil
		}
	}
	return "", errors.New("No executable for `certutil` found")
}

// Emulates the following
// /usr/local/opt/nss/bin/certutil -L -d '~/Library/Application Support/Firefox/Profiles/rrdlhe7o.default'
func (c certutil) listCertsFromDB(path cert8db) ([]cert8Item, error) {
	expath, err := c.getExecPath()
	if err != nil {
		return nil, err
	}

	args := []string{
		"-L",
		"-d", string(path),
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
	items := make([]cert8Item, 0)
	for {
		// read next line
		line, err := stdout.ReadString(byte('\n'))
		if err != nil && err != io.EOF {
			return nil, err
		}

		// convert the line into a cert8Item
		nick, trust := c.parseCert8Item(line)
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

		items = append(items, cert8Item{
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

func (c certutil) parseCert8Item(line string) (nick string, trust string) {
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

// /usr/local/opt/nss/bin/certutil -L -d "$dir" -n 'Microsoft IT SSL SHA2' -a
func (c certutil) readCertificatesForNick(path cert8db, nick string) ([]*x509.Certificate, error) {
	expath, err := c.getExecPath()
	if err != nil {
		return nil, err
	}

	args := []string{
		"-L",
		"-a",
		"-d", string(path),
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

	certs, err := pem.Parse(stdout.Bytes())
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// $ /usr/local/opt/nss/bin/certutil -M -n <nick> -t <trust-args> -d <dir>
func (c certutil) modifyTrustAttributes(path cert8db, nick, trustAttrs string) error {
	expath, err := c.getExecPath()
	if err != nil {
		return err
	}

	args := []string{
		"-M",
		"-n", nick,
		"-t", trustAttrs,
		"-d", string(path),
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
