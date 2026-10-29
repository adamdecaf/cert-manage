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

//go:build linux
// +build linux

package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

func enableDryRunCapture(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	SetDryRun(true)
	SetDryRunOutput(buf)
	t.Cleanup(func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	})
	return buf
}

func hashDir(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	snap := snapshotDir(t, dir)
	// stable order
	names := make([]string, 0, len(snap))
	for name := range snap {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		h.Write([]byte(name))
		h.Write(snap[name])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestLinuxDryRun_RestoreLeavesStoreUnchanged(t *testing.T) {
	s := linuxTestStore(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.ca.dir, "example.crt"), []byte("mutated-for-dry-run\n"), 0644); err != nil {
		t.Fatal(err)
	}
	before := hashDir(t, s.ca.dir)

	buf := enableDryRunCapture(t)
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore dry-run: %v", err)
	}
	after := hashDir(t, s.ca.dir)
	if before != after {
		t.Fatalf("dry-run Restore mutated store: before=%s after=%s", before, after)
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would restore linux") {
		t.Fatalf("missing restore plan header: %q", out)
	}
	if !strings.Contains(out, "source ") || !strings.Contains(out, "copy ") {
		t.Fatalf("plan missing source/copy details: %q", out)
	}
	if !strings.Contains(out, "example.crt") {
		t.Fatalf("plan missing example.crt: %q", out)
	}
}

func TestLinuxDryRun_AddLeavesStoreUnchanged(t *testing.T) {
	s := linuxTestStore(t)
	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil || len(certs) == 0 {
		t.Fatalf("load example.crt: %v", err)
	}
	beforeDir := hashDir(t, s.ca.dir)
	beforeAdd := hashDir(t, s.ca.add)
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	buf := enableDryRunCapture(t)
	if err := s.Add(certs); err != nil {
		t.Fatalf("Add dry-run: %v", err)
	}
	if hashDir(t, s.ca.dir) != beforeDir {
		t.Fatal("dry-run Add mutated ca.dir")
	}
	if hashDir(t, s.ca.add) != beforeAdd {
		t.Fatal("dry-run Add mutated ca.add")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would add certificates to linux") {
		t.Fatalf("missing add plan: %q", out)
	}
	if !strings.Contains(out, fp) {
		t.Fatalf("plan missing fingerprint %s: %q", fp, out)
	}
}

func TestLinuxDryRun_RemoveLeavesStoreUnchanged(t *testing.T) {
	s := linuxTestStore(t)
	before := hashDir(t, s.ca.dir)
	certs, err := certutil.FromFile(filepath.Join(s.ca.dir, "example.crt"))
	if err != nil || len(certs) == 0 {
		t.Fatalf("read example.crt: %v", err)
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	// Empty whitelist matches nothing, so example.crt would be removed.
	buf := enableDryRunCapture(t)
	if err := s.Remove(whitelist.Whitelist{}); err != nil {
		t.Fatalf("Remove dry-run: %v", err)
	}
	if hashDir(t, s.ca.dir) != before {
		t.Fatal("dry-run Remove mutated store")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would remove certificates from linux") {
		t.Fatalf("missing remove plan: %q", out)
	}
	if !strings.Contains(out, fp) {
		t.Fatalf("plan missing fingerprint %s: %q", out, fp)
	}
}

func TestLinuxDryRun_BackupMakesNoWrites(t *testing.T) {
	s := linuxTestStore(t)
	before := hashDir(t, s.ca.dir)
	home := os.Getenv("HOME")

	buf := enableDryRunCapture(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup dry-run: %v", err)
	}
	if hashDir(t, s.ca.dir) != before {
		t.Fatal("dry-run Backup mutated store")
	}
	// Prefer no writes at all: no backup tree under HOME.
	cm := filepath.Join(home, ".cert-manage")
	if st, err := os.Stat(cm); err == nil && st.IsDir() {
		entries, _ := os.ReadDir(cm)
		if len(entries) != 0 {
			t.Fatalf("dry-run Backup created files under %s: %v", cm, entries)
		}
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would backup linux") {
		t.Fatalf("missing backup plan: %q", out)
	}
}

// Prove the dry-run restore assertion is not vacuous: the same mutated store
// is actually rewritten by Restore when dry-run is off.
func TestLinuxDryRun_RestoreWithoutFlagDoesMutate(t *testing.T) {
	s := linuxTestStore(t)
	want := snapshotDir(t, s.ca.dir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.ca.dir, "example.crt"), []byte("mutated-control\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mutated := hashDir(t, s.ca.dir)

	SetDryRun(false)
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restored := hashDir(t, s.ca.dir)
	if mutated == restored {
		t.Fatal("Restore without dry-run did not change the mutated store")
	}
	assertDirSnapshotEqual(t, s.ca.dir, want)
}
