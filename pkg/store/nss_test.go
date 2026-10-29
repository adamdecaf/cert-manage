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
	"os"
	"path/filepath"
	"testing"
)

func TestStoreNSS_certdbDiscovery(t *testing.T) {
	// create a dir, add a 'cert.db' file and verify we can discover it
	tmp, err := os.MkdirTemp("", "nss-discovery")
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
	err = os.WriteFile(where, []byte("data"), 0644)
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

func TestStoreNSS_BackupCert9ProfileSet(t *testing.T) {
	// cert9 layout: cert9.db + key4.db + pkcs11.txt (copy whichever exist).
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"cert9.db":      []byte("cert9-payload\n"),
		"key4.db":       []byte("key4-payload\n"),
		"pkcs11.txt":    []byte("pkcs11-payload\n"),
		"unrelated.txt": []byte("should-not-be-backed-up\n"),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}
	st, err := os.Stat(latest)
	if err != nil || !st.IsDir() {
		t.Fatalf("latest backup should be a directory, got %s err=%v", latest, err)
	}
	for _, name := range []string{"cert9.db", "key4.db", "pkcs11.txt"} {
		got, err := os.ReadFile(filepath.Join(latest, name))
		if err != nil {
			t.Fatalf("missing %s in backup: %v", name, err)
		}
		if !bytes.Equal(got, files[name]) {
			t.Fatalf("%s content mismatch", name)
		}
	}
	if _, err := os.Stat(filepath.Join(latest, "unrelated.txt")); !os.IsNotExist(err) {
		t.Fatal("unrelated.txt should not be in the backup set")
	}
}

func TestStoreNSS_BackupCert8ProfileSet(t *testing.T) {
	// Legacy cert8 layout: cert8.db + key3.db + secmod.db.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"cert8.db":  []byte("cert8-payload\n"),
		"key3.db":   []byte("key3-payload\n"),
		"secmod.db": []byte("secmod-payload\n"),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}
	for _, name := range []string{"cert8.db", "key3.db", "secmod.db"} {
		got, err := os.ReadFile(filepath.Join(latest, name))
		if err != nil {
			t.Fatalf("missing %s in backup: %v", name, err)
		}
		if !bytes.Equal(got, files[name]) {
			t.Fatalf("%s content mismatch", name)
		}
	}
}

func TestStoreNSS_BackupCert9PartialSet(t *testing.T) {
	// Copy whichever members of the set exist (cert9.db required to select the set).
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("cert9-only\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "key4.db"), []byte("key4-only\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// pkcs11.txt intentionally absent

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(latest, "cert9.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(latest, "key4.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(latest, "pkcs11.txt")); !os.IsNotExist(err) {
		t.Fatal("pkcs11.txt should be absent from backup when missing in profile")
	}
}

func TestStoreNSS_BackupRestoreCert9ProfileRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	original := map[string][]byte{
		"cert9.db":   []byte("cert9-rt\n"),
		"key4.db":    []byte("key4-rt\n"),
		"pkcs11.txt": []byte("pkcs11-rt\n"),
	}
	for name, body := range original {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	for name := range original {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), []byte("mutated-"+name+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for name, want := range original {
		got, err := os.ReadFile(filepath.Join(nssdbDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s after restore: got %q want %q", name, got, want)
		}
	}
}

func TestStoreNSS_BackupRestoreCert8ProfileRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	original := map[string][]byte{
		"cert8.db":  []byte("cert8-rt\n"),
		"key3.db":   []byte("key3-rt\n"),
		"secmod.db": []byte("secmod-rt\n"),
	}
	for name, body := range original {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	for name := range original {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), []byte("mutated-"+name+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for name, want := range original {
		got, err := os.ReadFile(filepath.Join(nssdbDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s after restore: got %q want %q", name, got, want)
		}
	}
}

func TestStoreNSS_RestoreHonorsWhereFolder(t *testing.T) {
	// Restore(where) with a directory must copy the full profile set from that folder.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "key4.db"), []byte("live-key4\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alternate := t.TempDir()
	want := map[string][]byte{
		"cert9.db":   []byte("alt-cert9\n"),
		"key4.db":    []byte("alt-key4\n"),
		"pkcs11.txt": []byte("alt-pkcs11\n"),
	}
	for name, body := range want {
		if err := os.WriteFile(filepath.Join(alternate, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore(where folder): %v", err)
	}
	for name, body := range want {
		got, err := os.ReadFile(filepath.Join(nssdbDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("%s: got %q want %q", name, got, body)
		}
	}
}

func TestStoreNSS_RestoreHonorsWhereSingleFile(t *testing.T) {
	// Legacy single-file -file path still restores to cert9.db.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alternate := filepath.Join(t.TempDir(), "alternate-cert.db")
	alt := []byte("ALTERNATE-NSS-BACKUP\n")
	if err := os.WriteFile(alternate, alt, 0644); err != nil {
		t.Fatal(err)
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore(where file): %v", err)
	}
	got, err := os.ReadFile(filepath.Join(nssdbDir, "cert9.db"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, alt) {
		t.Fatalf("Restore did not honor where file; got %q want %q", got, alt)
	}
}
