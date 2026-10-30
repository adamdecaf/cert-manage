// Copyright 2026 Adam Shannon
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
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

// sslTestEnv points HOME/USERPROFILE at a temp dir and returns an sslStore
// backed by a temp PEM copied from testdata. Never touches /etc/ssl or real CAs.
func sslTestEnv(t *testing.T) (sslStore, string, []*x509.Certificate) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certs) < 2 {
		t.Fatalf("load lots.crt: len=%d err=%v", len(certs), err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := certutil.ToFile(path, certs); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemSSL(t, path)
	return sslStoreAt(path), path, certs
}

func refuseIfSystemSSL(t *testing.T, path string) {
	t.Helper()
	clean := filepath.Clean(path)
	if clean == filepath.Clean(defaultDarwinSSLCertPEM) {
		t.Fatalf("refusing to use real system path %s in tests", path)
	}
	if strings.HasPrefix(clean, "/etc/") || strings.HasPrefix(clean, "/System/") {
		t.Fatalf("refusing system path in tests: %s", path)
	}
}

func TestSSLStore_DefaultUnavailableOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("default SSLStore is available on Darwin")
	}
	s := SSLStore()
	_, err := s.List(nil)
	if err == nil {
		t.Fatal("expected error off Darwin")
	}
	if !strings.Contains(err.Error(), "Darwin") {
		t.Fatalf("error should mention Darwin, got %v", err)
	}
}

func TestSSLStore_ListBackupRestoreRoundTrip(t *testing.T) {
	s, path, want := sslTestEnv(t)

	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("List len=%d want %d", len(got), len(want))
	}

	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: %q err=%v", latest, err)
	}
	backupFile := filepath.Join(latest, sslBackupFilename)
	refuseIfSystemSSL(t, backupFile)
	backed, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatal(err)
	}
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backed, live) {
		t.Fatal("backup contents differ from live PEM")
	}

	// Mutate live, then restore.
	if err := certutil.ToFile(path, want[:1]); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	after, err := certutil.FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(want) {
		t.Fatalf("after restore len=%d want %d", len(after), len(want))
	}
}

func TestSSLStore_RestoreHonorsWhere(t *testing.T) {
	s, path, want := sslTestEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	altDir := t.TempDir()
	alt := filepath.Join(altDir, "alt.pem")
	if err := certutil.ToFile(alt, want[:1]); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemSSL(t, alt)
	if err := s.Restore(alt); err != nil {
		t.Fatalf("Restore(where): %v", err)
	}
	got, err := certutil.FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Restore(where) len=%d want 1", len(got))
	}
}

func TestSSLStore_RemoveAllowlistAndDryRun(t *testing.T) {
	s, path, certs := sslTestEnv(t)
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})

	var buf bytes.Buffer
	SetDryRunOutput(&buf)
	SetDryRun(true)
	defer func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	}()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove dry-run: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run Remove mutated the PEM")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run") {
		t.Fatalf("missing dry-run plan: %q", out)
	}

	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, err := certutil.FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("after allowlist len=%d want 1", len(got))
	}
	if certutil.GetHexSHA256Fingerprint(*got[0]) != certutil.GetHexSHA256Fingerprint(*certs[0]) {
		t.Fatal("kept unexpected certificate")
	}
}

func TestSSLStore_RemoveRefusesEmptyBundle(t *testing.T) {
	s, _, _ := sslTestEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	empty := allowlist.FromCertificates(nil)
	err := s.Remove(empty)
	if err == nil {
		t.Fatal("expected error refusing empty bundle")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error should mention empty, got %v", err)
	}
}

func TestSSLStore_DetectsOSUpdateDrift(t *testing.T) {
	s, path, certs := sslTestEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	if err := s.Remove(keep); err != nil {
		t.Fatal(err)
	}
	drifted, err := s.drifted()
	if err != nil {
		t.Fatal(err)
	}
	if drifted {
		t.Fatal("just-written bundle should match last-applied")
	}

	// Simulate a macOS update restoring a different Apple bundle.
	if err := certutil.ToFile(path, certs); err != nil {
		t.Fatal(err)
	}
	drifted, err = s.drifted()
	if err != nil {
		t.Fatal(err)
	}
	if !drifted {
		t.Fatal("expected drift after external rewrite of cert.pem")
	}

	var buf bytes.Buffer
	s.warnIfDrifted(&buf)
	msg := buf.String()
	if !strings.Contains(msg, "differs from the last trustprune write") {
		t.Fatalf("missing drift warning: %q", msg)
	}
	if !strings.Contains(msg, "restore -app ssl") {
		t.Fatalf("warning should tell user what to do next: %q", msg)
	}
}

func TestSSLStore_AddAppends(t *testing.T) {
	s, path, certs := sslTestEnv(t)
	extra, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil || len(extra) == 0 {
		t.Fatalf("example.crt: %v", err)
	}
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	before := len(certs)
	if err := s.Add(extra); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := certutil.FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != before+len(extra) {
		t.Fatalf("after add len=%d want %d", len(got), before+len(extra))
	}
}

func TestDetectSSL(t *testing.T) {
	st := detectSSL()
	if st.Name != "ssl" {
		t.Fatalf("name=%q", st.Name)
	}
	if runtime.GOOS != "darwin" {
		if st.Found {
			t.Fatal("ssl should not be found off Darwin")
		}
		return
	}
	// On Darwin CI the real file usually exists; we only assert shape.
	if st.Found && st.Path != defaultDarwinSSLCertPEM {
		t.Fatalf("path=%q want %s", st.Path, defaultDarwinSSLCertPEM)
	}
}

func TestSSLStore_RemoveDryRunRejectsEmpty(t *testing.T) {
	s, path, _ := sslTestEnv(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	SetDryRun(true)
	defer SetDryRun(false)
	empty := allowlist.FromCertificates(nil)
	err = s.Remove(empty)
	if err == nil {
		t.Fatal("dry-run should reject empty allowlist result")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run empty remove mutated PEM")
	}
}

func TestSSLStore_RestoreRejectsGarbageWhere(t *testing.T) {
	s, path, _ := sslTestEnv(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(t.TempDir(), "not-a-pem")
	if err := os.WriteFile(garbage, []byte("not-pem-at-all\n"), 0644); err != nil {
		t.Fatal(err)
	}
	SetDryRun(false)
	err = s.Restore(garbage)
	if err == nil {
		t.Fatal("expected restore to reject garbage source")
	}
	if !strings.Contains(err.Error(), "valid PEM") && !strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("unexpected error: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed restore overwrote live PEM")
	}
}

func TestSSLStore_LastAppliedOutsideBackupDir(t *testing.T) {
	s, path, certs := sslTestEnv(t)
	SetDryRun(false)
	// Add without Backup: records last-applied but creates no timestamp backup.
	extra, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil || len(extra) == 0 {
		t.Fatalf("example.crt: %v", err)
	}
	if err := s.Add(extra); err != nil {
		t.Fatal(err)
	}
	statePath, err := s.lastAppliedPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statePath, sslStateDirName) {
		t.Fatalf("last-applied path should be under %s: %s", sslStateDirName, statePath)
	}
	if strings.Contains(filepath.Dir(statePath), string(filepath.Separator)+sslBackupDir) ||
		strings.HasSuffix(filepath.Dir(statePath), sslBackupDir) {
		// Dir should be .../ssl-state, not .../ssl
		if filepath.Base(filepath.Dir(statePath)) == sslBackupDir {
			t.Fatalf("last-applied must not live under backup dir: %s", statePath)
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Restore("")
	if err == nil {
		t.Fatal("Restore with no backup should error, not use last-applied")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Restore without backup mutated live PEM")
	}
	_ = certs
}
