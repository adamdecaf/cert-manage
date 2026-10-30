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

//go:build linux
// +build linux

package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type pathMeta struct {
	mode    os.FileMode
	modTime time.Time
	data    []byte
	isDir   bool
}

func snapshotTree(t *testing.T, root string) map[string]pathMeta {
	t.Helper()
	out := make(map[string]pathMeta)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			rel = ""
		}
		meta := pathMeta{
			mode:    info.Mode(),
			modTime: info.ModTime(),
			isDir:   info.IsDir(),
		}
		if !info.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			meta.data = b
		}
		out[rel] = meta
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertTreeUnchanged(t *testing.T, root string, want map[string]pathMeta) {
	t.Helper()
	got := snapshotTree(t, root)
	if len(got) != len(want) {
		t.Fatalf("listing changed under %s: got %d entries want %d", root, len(got), len(want))
	}
	for rel, w := range want {
		g, ok := got[rel]
		if !ok {
			t.Errorf("missing path %q under %s", rel, root)
			continue
		}
		if g.isDir != w.isDir {
			t.Errorf("%s: isDir got %v want %v", rel, g.isDir, w.isDir)
		}
		if g.mode != w.mode {
			t.Errorf("%s: mode got %v want %v", rel, g.mode, w.mode)
		}
		if !g.modTime.Equal(w.modTime) {
			t.Errorf("%s: mtime got %v want %v", rel, g.modTime, w.modTime)
		}
		if !w.isDir && !bytes.Equal(g.data, w.data) {
			t.Errorf("%s: content changed", rel)
		}
	}
	for rel := range got {
		if _, ok := want[rel]; !ok {
			t.Errorf("unexpected path %q under %s", rel, root)
		}
	}
}

func listBasenames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// TestBackupDirMigration_LegacyReadOnly seeds backups under $HOME/.cert-manage
// (never the real home), then runs List/Backup/Restore and proves the legacy
// tree's listing, file contents, and mtimes stay byte-for-byte unchanged while
// new backups land under $HOME/.trustprune.
func TestBackupDirMigration_LegacyReadOnly(t *testing.T) {
	s := linuxTestStore(t)
	home := os.Getenv("HOME")
	if home == "" {
		t.Fatal("HOME unset; linuxTestStore must point HOME at a temp dir")
	}
	// Hard guard: never touch a real ~/.cert-manage outside the temp HOME.
	legacyRoot := filepath.Join(home, ".cert-manage")
	primaryRoot := filepath.Join(home, ".trustprune")
	if !strings.HasPrefix(filepath.Clean(legacyRoot)+string(os.PathSeparator), filepath.Clean(home)+string(os.PathSeparator)) {
		t.Fatalf("legacy root %s escapes temp HOME %s", legacyRoot, home)
	}

	oldStamp := "1000000001"
	oldDir := filepath.Join(legacyRoot, "linux", oldStamp)
	if err := os.MkdirAll(oldDir, 0755); err != nil {
		t.Fatal(err)
	}
	oldExample := []byte("legacy-example-ca\n")
	oldExtra := []byte("legacy-extra-ca\n")
	if err := os.WriteFile(filepath.Join(oldDir, "example.crt"), oldExample, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "extra.crt"), oldExtra, 0644); err != nil {
		t.Fatal(err)
	}
	// Pin mtimes so later comparisons are stable across the test.
	pinned := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	_ = filepath.Walk(legacyRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, pinned, pinned)
	})

	legacyBefore := snapshotTree(t, legacyRoot)
	legacyListingBefore := listBasenames(t, filepath.Join(legacyRoot, "linux"))

	if _, err := s.List(&ListOptions{Trusted: true}); err != nil {
		t.Fatalf("List: %v", err)
	}
	assertTreeUnchanged(t, legacyRoot, legacyBefore)

	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	assertTreeUnchanged(t, legacyRoot, legacyBefore)
	if got := listBasenames(t, filepath.Join(legacyRoot, "linux")); len(got) != len(legacyListingBefore) {
		t.Fatalf("legacy listing changed after Backup: got %v want %v", got, legacyListingBefore)
	}
	for i := range legacyListingBefore {
		if got := listBasenames(t, filepath.Join(legacyRoot, "linux")); got[i] != legacyListingBefore[i] {
			t.Fatalf("legacy listing changed after Backup: got %v want %v", got, legacyListingBefore)
		}
	}

	latest, err := s.GetLatestBackup()
	if err != nil {
		t.Fatalf("GetLatestBackup: %v", err)
	}
	if latest == "" {
		t.Fatal("GetLatestBackup returned empty")
	}
	if !strings.HasPrefix(latest, primaryRoot+string(os.PathSeparator)) {
		t.Fatalf("new backup should be under %s, got %s", primaryRoot, latest)
	}
	if strings.Contains(latest, ".cert-manage") {
		t.Fatalf("new backup must not land under legacy dir: %s", latest)
	}

	if err := os.WriteFile(filepath.Join(s.ca.dir, "example.crt"), []byte("mutated-live\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	assertTreeUnchanged(t, legacyRoot, legacyBefore)

	// Restore came from the new backup (live mirror of ca.dir at Backup time),
	// not by rewriting the legacy tree.
	restored, err := os.ReadFile(filepath.Join(s.ca.dir, "example.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(restored, oldExample) {
		t.Fatal("Restore unexpectedly used legacy backup contents")
	}
}

func TestGetLatestBackup_FallsBackToLegacy(t *testing.T) {
	s := linuxTestStore(t)
	home := os.Getenv("HOME")
	legacyDir := filepath.Join(home, ".cert-manage", "linux", "1000000099")
	if err := os.MkdirAll(legacyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "only-legacy.crt"), []byte("legacy-only\n"), 0644); err != nil {
		t.Fatal(err)
	}

	latest, err := s.GetLatestBackup()
	if err != nil {
		t.Fatalf("GetLatestBackup: %v", err)
	}
	if latest != legacyDir {
		t.Fatalf("GetLatestBackup=%q want legacy %q", latest, legacyDir)
	}
}

func TestGetLatestBackup_PrefersNewerAcrossDirs(t *testing.T) {
	s := linuxTestStore(t)
	home := os.Getenv("HOME")

	legacyDir := filepath.Join(home, ".cert-manage", "linux", "1000000200")
	primaryDir := filepath.Join(home, ".trustprune", "linux", "1000000100")
	for _, dir := range []string{legacyDir, primaryDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "marker.crt"), []byte(dir+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	latest, err := s.GetLatestBackup()
	if err != nil {
		t.Fatalf("GetLatestBackup: %v", err)
	}
	// Newer basename is the legacy 1000000200 entry.
	if latest != legacyDir {
		t.Fatalf("GetLatestBackup=%q want newer legacy %q", latest, legacyDir)
	}
}
