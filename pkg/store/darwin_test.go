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
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

func TestStoreDarwin__SystemCertPool(t *testing.T) {
	if !debug {
		t.Skip("skipping SystemCertPool() test")
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%d from Go's SystemCertPool()\n", len(pool.Subjects()))
}

func TestStoreDarwin__Backup(t *testing.T) {
	t.Skip("darwin support is wip")

	dir, err := getCertManageDir(darwinBackupDir)
	if err != nil {
		t.Fatal(err)
	}
	namesBefore, err := ioutil.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	s := platform()
	err = s.Backup()
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	// check we added one backup file
	namesAfter, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(namesAfter)-len(namesBefore) != 1 {
		t.Errorf("before=%d, after=%d", len(namesBefore), len(namesAfter))
	}

	// make sure backup file is non-empty
	latest, err := getLatestBackup(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(latest)

	fi, err := os.Stat(latest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() == 0 {
		t.Errorf("backup file %s is empty", latest)
	}
}

// There are various locations for certificates across OSX
// Mostly the Keychain groups the certificates (and trust policies)
// into a few groups
func TestStoreDarwin__locations(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("not on darwin based host")
	}

	paths := []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
		filepath.Join(file.HomeDir(), "/Library/Keychains/login.keychain"),
	}

	count := 0

	for _, p := range paths {
		certs, err := readInstalledCerts(p)
		if err != nil {
			t.Errorf("%s - err=%v", p, err)
		}
		count += len(certs)

		if !debug {
			continue
		}

		// Debug info
		fmt.Printf("%d certs from %s\n", len(certs), p)
		out := make([]string, 0)
		for i := range certs {
			if certs[i].Subject.CommonName != "" {
				out = append(out, fmt.Sprintf("  Subject CN=%v", certs[i].Subject.CommonName))
				continue
			}
			if certs[i].Issuer.CommonName != "" {
				out = append(out, fmt.Sprintf("  Issuer CN=%v", certs[i].Issuer.CommonName))
				continue
			}
		}
		sort.Strings(out)
		fmt.Printf("%s\n", strings.Join(out, "\n"))
	}

	if count == 0 {
		t.Errorf("Didn't find any certs from all %d paths", len(paths))
	}
}

func TestStoreDarwin__info(t *testing.T) {
	st := darwinStore{}
	info := st.GetInfo()
	if info == nil {
		t.Fatal("nil Info")
	}
	if info.Name == "" {
		t.Error("blank Name")
	}
	if info.Version == "" {
		t.Error("blank Version")
	}
}
