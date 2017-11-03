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
			"/usr/local/opt/nss/bin/certutil", // darwin
		},
	}

	// We're only going to support the current version (cert8.db)
	// https://wiki.mozilla.org/NSS_Shared_DB#Where_we_are_today
	cert8Filename = "cert8.db"
)

type nssStore struct {
	// paths represent the fs locations where cert8.db are stored
	// In the case of an app like Firefox this would be looking in the following locations:
	//  ~/Library/Application Support/Firefox/Profiles/*  (Darwin)
	// The expected result is a slice of directories that can be passed into certutil's -d option
	paths []cert8db
}

func collectNssSuggestions(sugs []string) []cert8db {
	kept := make([]cert8db, 0)
	for i := range sugs {
		// Glob and find a cert8.db file
		matches, err := filepath.Glob(sugs[i])
		if err != nil {
			if debug {
				fmt.Println(err.Error())
			}
			return nil
		}

		// Accumulate dirs with a cert8.db file
		for j := range matches {
			if containsCert8db(matches[j]) {
				kept = append(kept, cert8db(matches[j]))
			}
		}
	}
	return kept
}

func containsCert8db(p string) bool {
	s, err := os.Stat(filepath.Join(p, cert8Filename))
	if err != nil {
		if debug {
			fmt.Println(err.Error())
		}
		return false
	}
	return s.Size() > 0
}

// TODO(adam): impl
// we should be able to backup a cert8.db file directly
func (s nssStore) Backup() error {
	return nil
}

// List returns the installed (and trusted) certificates contained in a NSS cert8.db file
//
// To list certificates with the NSS `certutil` tool the following would be ran
// $ /usr/local/opt/nss/bin/certutil -L -d "$dir"
//
// Note: `dir` represents a directory path which contains a cert8.db file
func (s nssStore) List() ([]*x509.Certificate, error) {
	if len(s.paths) == 0 {
		return nil, errors.New("no firefox (default) profile discovered")
	}

	items, err := cutil.listCertsFromDB(s.paths[0])
	if err != nil {
		return nil, err
	}

	kept := make([]*x509.Certificate, 0)
	for i := range items {
		// TODO(adam): We should inspect the `items[i].trustAttrs` here
		kept = append(kept, items[i].certs...)
	}
	return kept, nil
}

// TODO(adam): impl
// $ /usr/local/opt/nss/bin/certutil -M --help
// -M              Modify trust attributes of certificate
//    -n cert-name      The nickname of the cert to modify
//    -t trustargs      Set the certificate trust attributes (see -A above)
//    -d certdir        Cert database directory (default is ~/.netscape)
//    -P dbprefix       Cert & Key database prefix
func (s nssStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

// TODO(adam): impl
func (s nssStore) Restore(where string) error {
	return nil
}

// cert8db represents a fs path for a cert8.db file
type cert8db string

// cert8Item represents an x509 Certificate with the NSS trust attributes
type cert8Item struct {
	certs []*x509.Certificate
	// TODO(adam): this will probably need better thought out
	trustAttrs string
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
			fmt.Printf("Command was:\n %s", strings.Join(cmd.Args, " "))
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
		// "-n", fmt.Sprintf(`'%s'`, nick),
		"-n", nick,
	}
	cmd := exec.Command(expath, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was:\n %s", strings.Join(cmd.Args, " "))
		}
		return nil, err
	}

	certs, err := pem.Parse(stdout.Bytes())
	if err != nil {
		return nil, err
	}

	return certs, nil
}
