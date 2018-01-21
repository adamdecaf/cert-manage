// +build windows

package store

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
	"golang.org/x/crypto/pkcs12"
)

// Docs:
// https://msdn.microsoft.com/en-us/library/e78byta0(v=vs.110).aspx
// https://social.technet.microsoft.com/wiki/contents/articles/31633.microsoft-trusted-root-program-requirements.aspx
// https://social.technet.microsoft.com/wiki/contents/articles/31680.microsoft-trusted-root-certificate-program-updates.aspx

// https://blogs.technet.microsoft.com/yuridiogenes/2011/04/20/exporting-certificates-using-certutil/
// https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732443(v=ws.11)

// Certificate store locations:
// - https://superuser.com/questions/411909/where-is-the-certificate-folder-in-windows-7
// - https://msdn.microsoft.com/en-us/library/windows/desktop/aa388136(v=vs.85).aspx

var (
	// C:\Users>certutil -enumstore
	// Note: Not all stores are named here, some aren't "web" related
	// e.g. 'Remote Desktop' or SmartCardRoot
	windowsStoreNames = []string{
		"My",       // Personal
		"Root",     // "Trusted Root Certification Authorities"
		"Trust",    // "Enterprise Trust"
		"CA",       // "Intermediate Certification Authorities"
		"AuthRoot", // "Third-Party Root Certification Authorities"
	}
)

type windowsStore struct{}

func platform() Store {
	return windowsStore{}
}

func (s windowsStore) Backup() error {
	return nil
}

func (s windowsStore) List() ([]*x509.Certificate, error) {
	var accum []*x509.Certificate
	for i := range windowsStoreNames {
		certs, err := s.certsFromStore(windowsStoreNames[i])
		if err != nil {
			return nil, err
		}
		accum = append(accum, certs...)
	}
	return accum, nil
}

func (s windowsStore) certsFromStore(store string) ([]*x509.Certificate, error) {
	serials, err := s.certSerialsFromStore(store)
	if err != nil {
		return nil, err
	}
	var accum []*x509.Certificate
	for i := range serials {
		cert, err := s.exportCertFromStore(serials[i], store)
		if err != nil {
			return nil, err
		}
		if cert != nil {
			accum = append(accum, cert)
		}
	}
	return accum, nil
}

func (s windowsStore) certSerialsFromStore(store string) ([]string, error) {
	cmd := exec.Command("certutil", "-store", store)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("error reading serials from store %s err=%v", store, err)
	}
	return s.readCertSerials(string(stdout.Bytes()))
}

var (
	// C:\Users>certutil -store Root
	// Root "Trusted Root Certification Authorities"
	// ================ Certificate 0 ================
	// Serial Number: 72696afcd5edce864658141cb588a3a8
	winSerialNumberPrefix = "Serial Number:"
	winSerialNumberRegex  = regexp.MustCompile(fmt.Sprintf(`%s ([0-9a-f]+)\r`, winSerialNumberPrefix))
)

func (s windowsStore) readCertSerials(out string) ([]string, error) {
	matches := winSerialNumberRegex.FindAllString(out, -1)
	for i := range matches {
		matches[i] = strings.TrimSpace(strings.Replace(matches[i], winSerialNumberPrefix, "", -1))
	}
	return matches, nil
}

var (
	pfxPassword = "password"
)

func (s windowsStore) exportCertFromStore(serial, store string) (*x509.Certificate, error) {
	tmp, err := ioutil.TempFile("", "cert-manage-windows")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file, err=%v", err)
	}

	// close and rm file, we got a unique name
	// This avoids: "The process cannot access the file because it is being used by another process."
	err = tmp.Close()
	if err != nil {
		return nil, err
	}
	err = os.Remove(tmp.Name())
	if err != nil {
		return nil, err
	}
	defer func() { // then make sure it's gone afterwords
		if file.Exists(tmp.Name()) {
			os.Remove(tmp.Name())
		}
	}()

	// export cert into PKCS #12 format
	out, err := exec.Command("certutil", "-exportPFX", "-f", "-p", pfxPassword, store, serial, tmp.Name()).CombinedOutput()
	fmt.Printf("%q\n", string(out))
	if err != nil {
		if bytes.Contains(out, []byte("Keyset does not exist")) {
			// TODO(adam): Issue repair? That might muck with the store(s)
			return nil, nil
		}
		return nil, fmt.Errorf("error exporting cert %q (from %s) to PKCS #12 err=%q", serial, store, err)
	}

	bs, err := ioutil.ReadFile(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("error reading temp file, err=%v", err)
	}
	_, cert, err := pkcs12.Decode(bs, pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("error parsing PKCS #12 of serial %q from %s, err=%q", serial, store, err)
	}
	return cert, nil
}

func (s windowsStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s windowsStore) Restore(where string) error {
	return nil
}
