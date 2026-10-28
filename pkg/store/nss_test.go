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
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStoreNSS_certdbDiscovery(t *testing.T) {
	// create a dir, add a 'cert.db' file and verify we can discover it
	tmp, err := ioutil.TempDir("", "nss-discovery")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmp)

	// Verify we don't find anything in an empty dir
	if containsCertdb(tmp) {
		t.Errorf("%s shouldn't contain a cert.db", tmp)
	}

	// Create a blank cert.db file
	where := filepath.Join(tmp, "cert9.db")
	err = ioutil.WriteFile(where, []byte("data"), 0644)
	if err != nil {
		t.Error(err)
	}

	// Now we should find the cert.db path
	if !containsCertdb(tmp) {
		t.Errorf("should have found cert.db in %s", tmp)
	}
}

func TestStoreNSS_trustedForSSL(t *testing.T) {
	trusted := map[string]bool{
		// trusted attrs
		"c,c,c": true,
		",,":    true,
		"CT,,":  true,
		"u,,":   true,
		"wC,,":  true,
		// not trusted
		"p,p,p": false,
		"p,,":   false,
	}
	for attrs, answer := range trusted {
		item := certdbItem{trustAttrs: attrs}
		if res := item.trustedForSSL(); res != answer {
			t.Errorf("attrs (%s), trustedForSSL()=%v should be %v", attrs, res, answer)
		}
	}
}

func TestStoreNSS_BackupCopiesCert9DB(t *testing.T) {
	// Regression for #142: Backup must copy cert9.db (or cert8.db), not
	// filepath.Join(nssdbDir, filepath.Base(nssdbDir)).
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	cert9 := []byte("cert9.db unique payload for issue 142\n")
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), cert9, 0644); err != nil {
		t.Fatal(err)
	}

	// The old buggy source path must still not exist (guards against regressing
	// to joining the directory with its own basename).
	wrongSrc := filepath.Join(nssdbDir, filepath.Base(nssdbDir))
	if _, err := os.Stat(wrongSrc); !os.IsNotExist(err) {
		t.Fatalf("precondition: %s must not exist (stat err=%v)", wrongSrc, err)
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup() should copy cert9.db: %v", err)
	}

	backupRoot := filepath.Join(home, ".cert-manage")
	if runtime.GOOS == "darwin" {
		backupRoot = filepath.Join(home, "Library", "cert-manage")
	}
	found := findBytesUnder(t, backupRoot, cert9)
	if found == "" {
		t.Fatal("cert9.db content missing from backup")
	}

	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}
	got, err := os.ReadFile(latest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cert9) {
		t.Fatalf("latest backup bytes mismatch: got %q want %q", got, cert9)
	}
}

func TestStoreNSS_BackupFallsBackToCert8DB(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	cert8 := []byte("cert8.db unique payload\n")
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert8.db"), cert8, 0644); err != nil {
		t.Fatal(err)
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup() should copy cert8.db when cert9.db is absent: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}
	got, err := os.ReadFile(latest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cert8) {
		t.Fatalf("latest backup bytes mismatch: got %q want %q", got, cert8)
	}
}

func findBytesUnder(t *testing.T, root string, payload []byte) string {
	t.Helper()
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return ""
	}
	var found string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Equal(b, payload) || bytes.Contains(b, payload) {
			found = path
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}
