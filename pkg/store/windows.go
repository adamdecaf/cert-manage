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

//go:build windows
// +build windows

package store

import (
	"crypto/x509"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
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

	winSetup sync.Once
	winRootStore *windowsRootStore
)

type windowsStore struct {}

func (s windowsStore) setup() {
	winSetup.Do(func() {
		store, err := loadWindowsRootStore("Root")
		if err != nil {
			panic(fmt.Sprintf("problem loading windows store: %v", err))
		}
		winRootStore = &store
	})
}

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
	// From https://stackoverflow.com/a/42778990
	out, err := exec.Command("systeminfo").CombinedOutput()
	if err != nil {
		return &Info{
			Name: "Windows",
		}
	}
	info := string(out)

	nameRegex := regexp.MustCompile(`OS Name:\s*([\w\s]*)`)
	versionRegex := regexp.MustCompile(`OS Version:\s*([\w\s\.\/]*)`)

	name := strings.TrimPrefix(nameRegex.FindString(info), "OS Name:")
	version := strings.TrimPrefix(versionRegex.FindString(info), "OS Version:")

	return &Info{
		Name:    strings.Split(strings.TrimSpace(name), "\r")[0],
		Version: strings.Split(strings.TrimSpace(version), "\r")[0],
	}
}

func (s windowsStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	s.setup()
	return winRootStore.getCertificates()
}

func (s windowsStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s windowsStore) Restore(where string) error {
	return nil
}

var (
	modcrypt32                           = syscall.NewLazyDLL("crypt32.dll")
	procCertCloseStore                   = modcrypt32.NewProc("CertCloseStore")
	procCertDuplicateCertificateContext  = modcrypt32.NewProc("CertDuplicateCertificateContext")
	procCertEnumCertificatesInStore      = modcrypt32.NewProc("CertEnumCertificatesInStore")
	procCertOpenSystemStoreW             = modcrypt32.NewProc("CertOpenSystemStoreW")
)

// windowsRootStore represents a pointer to a Root Certificate store on Windows
// This code is inspired from FiloSottile/mkcert's truststore_windows.go, but adapted
// for this projects usecase.
type windowsRootStore uintptr

func loadWindowsRootStore(name string) (windowsRootStore, error) {
	store, _, err := procCertOpenSystemStoreW.Call(0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))))
	if store != 0 {
		return windowsRootStore(store), nil
	}
	return 0, fmt.Errorf("problem opening windows root store: %v", err)
}

func (w windowsRootStore) close() error {
	ret, _, err := procCertCloseStore.Call(uintptr(w), 0)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("problem closing windows root store: %v", err)
}

func (w windowsRootStore) getCertificates() ([]*x509.Certificate, error) {
	var cert *syscall.CertContext
	pool := certutil.Pool{}
	for {
		// Read next certificate
		certPtr, _, err := procCertEnumCertificatesInStore.Call(uintptr(w), uintptr(unsafe.Pointer(cert)))
		if cert = (*syscall.CertContext)(unsafe.Pointer(certPtr)); cert == nil {
			// TODO(adam): figure out from FiloSottile/mkcert what "0x80092004" is exactly for..
			if errno, ok := err.(syscall.Errno); ok && errno == 0x80092004 {
				break
			}
			return nil, fmt.Errorf("problem enumerating certs: %v", err)
		}

		// Parse cert
		// Using C.GoBytes requires gcc, but crypto/x509 uses this trick too
		// https://github.com/golang/go/blob/22e17d0ac7db5321a0f6e073bd0afb949f44dd70/src/crypto/x509/root_windows.go#L70
		certBytes := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:cert.Length]
		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}
		pool.Add(parsedCert)
	}
	return pool.GetCertificates(), nil
}
