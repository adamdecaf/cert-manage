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

package store

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLocateChromeNSS(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("unix-style .pki/nssdb layout")
	}

	home, err := ioutil.TempDir("", "cert-manage-chrome-nss")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)

	if where, ok := locateChromeNSS(home); ok {
		t.Fatalf("empty home should not find nssdb, got %s", where)
	}
	if where, ok := locateChromeNSS(""); ok {
		t.Fatalf("blank home should not find nssdb, got %s", where)
	}

	nss := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(nss, 0755); err != nil {
		t.Fatal(err)
	}
	where, ok := locateChromeNSS(home)
	if !ok || where != nss {
		t.Fatalf("want %s found, got where=%s ok=%v", nss, where, ok)
	}
}

func TestLocateFirefoxProfile(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("unix-style firefox profile layout")
	}

	home, err := ioutil.TempDir("", "cert-manage-ff-profile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)

	suggestions := []string{filepath.Join(home, ".mozilla/firefox/*.default")}
	if where, ok := locateFirefoxProfile(suggestions); ok {
		t.Fatalf("empty profiles should not match, got %s", where)
	}

	// Profile without a cert db is ignored.
	empty := filepath.Join(home, ".mozilla", "firefox", "aaaa.default")
	if err := os.MkdirAll(empty, 0755); err != nil {
		t.Fatal(err)
	}
	if where, ok := locateFirefoxProfile(suggestions); ok {
		t.Fatalf("profile without certdb should not match, got %s", where)
	}

	good := filepath.Join(home, ".mozilla", "firefox", "bbbb.default")
	if err := os.MkdirAll(good, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(good, "cert9.db"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	where, ok := locateFirefoxProfile(suggestions)
	if !ok || where != good {
		t.Fatalf("want %s found, got where=%s ok=%v", good, where, ok)
	}
}

func TestDetectStatusesShape(t *testing.T) {
	t.Parallel()

	statuses := DetectStatuses()
	apps := GetApps()
	if len(statuses) != len(apps)+1 {
		t.Fatalf("want %d statuses (apps+platform), got %d", len(apps)+1, len(statuses))
	}
	for i, name := range apps {
		if statuses[i].Name != name {
			t.Errorf("statuses[%d].Name=%q want %q", i, statuses[i].Name, name)
		}
	}
	last := statuses[len(statuses)-1]
	if last.Name != "platform" {
		t.Errorf("last status name=%q want platform", last.Name)
	}
}

func TestDetectJavaWithTempKeystore(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("unix java home layout")
	}

	dir, err := ioutil.TempDir("", "cert-manage-java-detect")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	ksDir := filepath.Join(dir, "lib", "security")
	if err := os.MkdirAll(ksDir, 0755); err != nil {
		t.Fatal(err)
	}
	ksPath := filepath.Join(ksDir, "cacerts")
	if err := ioutil.WriteFile(ksPath, []byte("fake-keystore"), 0644); err != nil {
		t.Fatal(err)
	}

	orig := ktool
	defer func() { ktool = orig }()
	ktool = keytool{
		javahome:              dir,
		javaInstallPaths:      nil,
		relativeKeystorePaths: []string{"/lib/security/cacerts"},
	}

	st := detectJava()
	if !st.Found || st.Path != ksPath {
		t.Fatalf("detectJava = %#v, want found path %s", st, ksPath)
	}
}

func TestDetectOpenSSLWithTempPath(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("openssl store unsupported on windows")
	}

	dir, err := ioutil.TempDir("", "cert-manage-openssl-detect")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	bundle := filepath.Join(dir, "ca-certificates.crt")
	if err := ioutil.WriteFile(bundle, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	orig := openSSLCertPaths
	defer func() { openSSLCertPaths = orig }()
	openSSLCertPaths = []string{bundle}

	st := detectOpenSSL()
	if !st.Found || st.Path != bundle {
		t.Fatalf("detectOpenSSL = %#v, want found path %s", st, bundle)
	}
}
