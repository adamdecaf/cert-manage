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
	path := cert8db(`/Users/adam/Library/Application Support/Firefox/Profiles/rrdlhe7o.default`)
	items, err := cutil.listCertsFromDB(path)
	if err != nil {
		return nil, err
	}

	// debug for now
	for i := range items {
		fmt.Println(items[i])
	}

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
			"/usr/local/opt/nss/bin/certutil", // darwin
		},
	}
)

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
		"-d", fmt.Sprintf(`'%s'`, string(path)),
	}
	cmd := exec.Command(expath, args...)
	fmt.Println(cmd.Args)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		// if debug {
		fmt.Println(stderr.String())
		// }
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
			break
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

	if strings.Contains(line, "Certificate Nickname") {
		return
	}
	if strings.Contains(line, "SSL,S/MIME,JAR/XPI") {
		return
	}

	// Pull out the 'Certificate Nickname'
	// Examples:
	// DigiCert SHA2 Extended Validation Server CA                  ,,
	// Symantec Class 3 Extended Validation SHA256 SSL CA           CT,C,C
	split := strings.Split(line, " ")

	nick = strings.Join(split[:len(split)-1], " ")
	trust = split[len(split)-1:][0] // last

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
		"-d", fmt.Sprintf(`'%s'`, string(path)),
		"-n", fmt.Sprintf("'%s'", nick),
		"-a",
	}
	cmd := exec.Command(expath, args...)
	fmt.Println(cmd.Args)
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
