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

func TestStoreNSS_BackupWrongPathMissingCert9DB(t *testing.T) {
	// TODO(#142): Backup joins foundCertdbLocation with its own basename instead of
	// cert9.db/cert8.db, so the real NSS DB is never backed up.
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

	wrongSrc := filepath.Join(nssdbDir, filepath.Base(nssdbDir))
	if _, err := os.Stat(wrongSrc); !os.IsNotExist(err) {
		t.Fatalf("precondition: %s must not exist so Backup hits #142 (stat err=%v)", wrongSrc, err)
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	err := s.Backup()

	backupRoot := filepath.Join(home, ".cert-manage")
	if runtime.GOOS == "darwin" {
		backupRoot = filepath.Join(home, "Library", "cert-manage")
	}
	found := findBytesUnder(t, backupRoot, cert9)

	// Current (buggy) behavior: CopyFile(nssdbDir+"/"+basename) fails because
	// that path does not exist when only cert9.db is present, so Backup errors
	// and cert9.db is never copied.
	if err == nil {
		t.Error("Backup() succeeded; current #142 behavior is an error because the source path is nssdbDir/<basename>, not cert9.db")
	}
	if found != "" {
		t.Errorf("cert9.db content appeared at %s; #142 is that the NSS DB is never backed up", found)
	}

	// Expected-correct behavior once #142 is fixed:
	//
	//	if err != nil {
	//		t.Fatalf("Backup() should copy cert9.db: %v", err)
	//	}
	//	if found == "" {
	//		t.Fatal("cert9.db content missing from backup")
	//	}
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
