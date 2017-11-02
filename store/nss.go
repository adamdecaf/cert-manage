package store

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/adamdecaf/cert-manage/tools/file"
	"github.com/adamdecaf/cert-manage/tools/pem"
	"github.com/adamdecaf/cert-manage/whitelist"
)

// Users of NSS
// Chrome: Linux
// Firefox: Darwin, Linux, Windows

// Docs:
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Tools/certutil
// - https://wiki.mozilla.org/NSS_Shared_DB
// - https://www.chromium.org/Home/chromium-security/root-ca-policy
//   - https://chromium.googlesource.com/chromium/src/+/master/docs/linux_cert_management.md
//   - https://wiki.mozilla.org/NSS_Shared_DB_And_LINUX

type nssStore struct{}

func NssStore() Store {
	return nssStore{}
}

func (s nssStore) Backup() error {
	return nil
}

// TODO(adam): this needs to accept an "nssType": firefox, thunderbird, etc
// which will let it figure out how better to list the contents from cert8.db
//
// TODO(adam): We'll need to discover the nss install (and bin/) location
// for whatever platform we're on.
//
// dir='/Users/adam/Library/Application Support/Firefox/Profiles/rrdlhe7o.default'
// $ /usr/local/opt/nss/bin/certutil -L -d "$dir" | grep banno
// banno_ca                                                     CT,C,C
//
// Listing certs
// $ /usr/local/opt/nss/bin/certutil -L -d "$dir"
//
// Certificate Nickname                                         Trust Attributes
//                                                              SSL,S/MIME,JAR/XPI
//
// USERTrust RSA Certification Authority                        ,,
// Microsoft IT SSL SHA2                                        ,,
// SSL.com High Assurance CA                                    ,,
// DigiCert SHA2 Extended Validation Server CA                  ,,
// Amazon Root CA 1                                             ,,
// ..
//
// Return one cert (PEM)
// /usr/local/opt/nss/bin/certutil -L -d "$dir" -n 'Microsoft IT SSL SHA2' -a
func (s nssStore) List() ([]*x509.Certificate, error) {
	return nil, nil
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

func (s nssStore) Restore(where string) error {
	return nil
}

var (
	cutil = certutil{
		execPaths: []string{
			"/usr/local/opt/nss/bin/certutil",
		},
	}
)

// cert8db represents a fs path for a cert8.db file
type cert8db string

// certWithTrust represents an x509 Certificate with the NSS trust attributes
type certWithTrust struct {
	cert        *x509.Certificate
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
func (c certutil) readNssCertNicks(path cert8db) ([]string, error) {
	expath, err := c.getExecPath()
	if err != nil {
		return nil, err
	}

	args := []string{"-L", "-d", string(path)}

	cmd := exec.Command(expath, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	// parse out each 'Certificate Nickname' field
	// there are some header lines that are either whitespace or contain the following:
	//
	// Certificate Nickname                                         Trust Attributes
	// SSL,S/MIME,JAR/XPI
	//
	var line string
	nicks := make([]string, 0)
	for {
		// Quit if the last error was io.EOF (we're done)
		if err != nil && err == io.EOF {
			break
		}

		line, err = stdout.ReadString(byte('\n'))
		if err != nil && err != io.EOF {
			return nil, err // quit early if we ran into a non-EOF error
		}

		// TODO(adam): we actually need to split this apart into 'Certificate Nickname' and 'Trust Attributes'

		line = strings.TrimSpace(line)
		if strings.Contains(line, "Certificate Nickname") || strings.Contains(line, "SSL,S/MIME,JAR/XPI") {
			continue
		}

		// Pull out the 'Certificate Nickname'
		// Examples:
		// DigiCert SHA2 Extended Validation Server CA                  ,,
		// Symantec Class 3 Extended Validation SHA256 SSL CA           CT,C,C
		//
		split := strings.Split(line, " ")
		nick := strings.Join(split[:len(split)-1], " ")
		nicks = append(nicks, nick)
	}

	return nicks, nil
}

// readCertificatesWithTrust
func (c certutil) readCertificatesWithTrust(path cert8db) ([]certWithTrust, error) {
	nicks, err := c.readNssCertNicks(path)
	if err != nil {
		return nil, err
	}

	// todo(adam): Collect the
	certs := make([]*x509.Certificate, 0)
	for i := range nicks {
		cs, err := c.readCertificates(path, nicks[i])
		if err != nil {
			return nil, err
		}
		certs = append(certs, cs...)
	}

	return certs, nil
}

// /usr/local/opt/nss/bin/certutil -L -d "$dir" -n 'Microsoft IT SSL SHA2' -a
func (c certutil) readCertificates(path cert8db, nick string) ([]*x509.Certificate, error) {
	expath, err := c.getExecPath()
	if err != nil {
		return nil, err
	}

	args := []string{"-L", "-d", string(path), "-n", fmt.Sprintf("'%s'", nick), "-a"}
	cmd := exec.Command(expath, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	certs, err := pem.Parse(stdout.Bytes())
	if err != nil {
		return nil, err
	}

	return certs, nil
}
