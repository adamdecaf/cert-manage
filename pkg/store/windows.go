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

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
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

func (s windowsStore) Add(certs []*x509.Certificate) error {
	return nil
}

func (s windowsStore) Backup() error {
	return nil
}

func (s windowsStore) GetLatestBackup() (string, error) {
	return "", nil
}

func (s windowsStore) GetInfo() *Info {
	return &Info{
		Name:    "Windows",
		Version: s.version(),
	}
}

func (s windowsStore) version() string {
	out, err := exec.Command("ver").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (s windowsStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
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
	if debug {
		fmt.Printf("%q\n", string(out))
	}
	if err != nil {
		if debug && bytes.Contains(out, []byte("Keyset does not exist")) {
			// TODO(adam): Issue repair? That might muck with the store(s)
			return nil, nil
		}
		if debug && bytes.Contains(out, []byte("Cannot find object or property.")) {
			// TODO(adam): uhh..?
			// CertUtil: -exportPFX command FAILED: 0x80092004 (-2146885628 CRYPT_E_NOT_FOUND)\r\nCertUtil: Cannot find object or property.
			return nil, nil
		}
		return nil, fmt.Errorf("error exporting cert %q (from %s) to PKCS #12 err=%q", serial, store, err)
	}

	bs, err := ioutil.ReadFile(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("error reading temp file, err=%v", err)
	}
	cert, err := certutil.DecodePKCS12(bs, pfxPassword)
	if err != nil {
		if debug && strings.Contains(err.Error(), "expected exactly two items in the authenticated safe") {
			// TODO(adam): https://github.com/golang/go/issues/23499
			return nil, nil
		}
		if debug && strings.Contains(err.Error(), "OID 1.3.6.1.4.1.311.17.2") {
			// TODO(adam): http://oidref.com/1.3.6.1.4.1.311.17.2
			return nil, nil
		}
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
