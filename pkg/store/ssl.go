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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

const (
	// defaultDarwinSSLCertPEM is the system OpenSSL/LibreSSL trust bundle that
	// curl, git, python3, and other CLI tools read on macOS. Apple's keychain
	// blocks do not apply to this file (see Apple support HT149555 / eMudhra).
	defaultDarwinSSLCertPEM = "/etc/ssl/cert.pem"

	sslBackupDir       = "ssl"
	sslBackupFilename  = "cert.pem"
	sslLastAppliedName = "last-applied.sha256"
)

// sslStore manages a PEM certificate bundle file (Darwin /etc/ssl/cert.pem by
// default). The path field is overridable for tests so real system CAs are
// never touched.
type sslStore struct {
	path string
}

// SSLStore returns the Darwin /etc/ssl/cert.pem store. On non-Darwin platforms
// the store reports itself unavailable; use sslStoreAt in tests to inject a
// temporary PEM path on any OS.
func SSLStore() Store {
	if runtime.GOOS != "darwin" {
		return sslStore{}
	}
	return sslStore{path: defaultDarwinSSLCertPEM}
}

// sslStoreAt returns an sslStore pointed at path. Intended for tests.
func sslStoreAt(path string) sslStore {
	return sslStore{path: path}
}

func (s sslStore) certPath() (string, error) {
	if s.path == "" {
		return "", errors.New("ssl store is only available on Darwin; use -app ssl on macOS where /etc/ssl/cert.pem exists")
	}
	return s.path, nil
}

func (s sslStore) GetInfo() *Info {
	info := &Info{Name: "ssl"}
	path, err := s.certPath()
	if err != nil {
		return info
	}
	info.Path = path
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		info.Version = fmt.Sprintf("%d bytes", st.Size())
	}
	return info
}

func (s sslStore) List(_ *ListOptions) ([]*x509.Certificate, error) {
	path, err := s.certPath()
	if err != nil {
		return nil, err
	}
	if !file.Exists(path) {
		return nil, fmt.Errorf("ssl bundle not found at %s; expected Darwin /etc/ssl/cert.pem", path)
	}
	certs, err := certutil.FromFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	s.warnIfDrifted(os.Stderr)
	return certs, nil
}

func (s sslStore) Add(certs []*x509.Certificate) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("ssl bundle not found at %s; create or restore it before adding certificates", path)
	}
	existing, err := certutil.FromFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if DryRun() {
		details := reportDryRunCerts("add", certs)
		reportDryRun("add certificates to", "ssl", path, details...)
		return nil
	}
	merged := append([]*x509.Certificate{}, existing...)
	merged = append(merged, certs...)
	return s.replaceBundle(merged)
}

func (s sslStore) Backup() error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("ssl bundle not found at %s; nothing to back up", path)
	}
	if DryRun() {
		reportDryRun("backup", "ssl", path,
			fmt.Sprintf("copy %s into %s/%s/<timestamp>/%s", path, backupParentDisplay(), sslBackupDir, sslBackupFilename))
		return nil
	}
	s.warnIfDrifted(os.Stderr)
	dir, err := getCertManageDir(fmt.Sprintf("%s/%d", sslBackupDir, time.Now().Unix()))
	if err != nil {
		return err
	}
	dst := filepath.Join(dir, sslBackupFilename)
	if err := file.CopyFile(path, dst); err != nil {
		return fmt.Errorf("backup %s to %s: %w", path, dst, err)
	}
	return nil
}

func (s sslStore) GetLatestBackup() (string, error) {
	dir, err := getLatestStoreBackup(sslBackupDir)
	if err != nil {
		return "", fmt.Errorf("getLatestBackup: error getting ssl backup directory err=%w", err)
	}
	return dir, nil
}

func (s sslStore) Remove(al allowlist.Allowlist) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if !file.Exists(path) {
		return fmt.Errorf("ssl bundle not found at %s; nothing to allowlist", path)
	}
	certs, err := certutil.FromFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var kept, removed []*x509.Certificate
	for i := range certs {
		if al.Matches(certs[i]) {
			kept = append(kept, certs[i])
		} else {
			removed = append(removed, certs[i])
		}
	}

	if DryRun() {
		details := reportDryRunCerts("remove", removed)
		reportDryRun("remove certificates from", "ssl", path, details...)
		return nil
	}
	if len(kept) == 0 {
		return fmt.Errorf("allowlist would leave %s empty; refusing to write an empty bundle. Adjust the allowlist or restore from backup", path)
	}
	return s.replaceBundle(kept)
}

func (s sslStore) Restore(where string) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	src := where
	if src == "" {
		src, err = s.GetLatestBackup()
		if err != nil {
			return err
		}
		if src == "" {
			return fmt.Errorf("no ssl backup found under %s/%s; run: trustprune backup -app ssl", backupParentDisplay(), sslBackupDir)
		}
	}
	srcFile, err := sslBackupFile(src)
	if err != nil {
		return err
	}
	if DryRun() {
		reportDryRun("restore", "ssl", path,
			fmt.Sprintf("source %s", srcFile),
			fmt.Sprintf("copy %s -> %s", srcFile, path))
		return nil
	}
	if err := file.SudoCopyFile(srcFile, path); err != nil {
		return fmt.Errorf("restore %s from %s: %w; re-run with permission to write that path (often sudo)", path, srcFile, err)
	}
	return s.recordLastAppliedFromFile(srcFile)
}

// replaceBundle writes certs to a temp PEM then installs it at the store path
// with an atomic-enough sudo copy. The live file is left untouched until the
// temp write succeeds.
func (s sslStore) replaceBundle(certs []*x509.Certificate) error {
	path, err := s.certPath()
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return fmt.Errorf("refusing to write an empty bundle to %s", path)
	}
	tmp, err := os.CreateTemp("", "trustprune-ssl-*.pem")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpName) }()

	if err := certutil.ToFile(tmpName, certs); err != nil {
		return fmt.Errorf("stage ssl bundle: %w", err)
	}
	if err := file.SudoCopyFile(tmpName, path); err != nil {
		return fmt.Errorf("write %s: %w; re-run with permission to write that path (often sudo)", path, err)
	}
	return s.recordLastAppliedFromFile(tmpName)
}

func sslBackupFile(src string) (string, error) {
	st, err := os.Stat(src)
	if err != nil {
		return "", fmt.Errorf("ssl backup %s: %w", src, err)
	}
	if st.IsDir() {
		candidate := filepath.Join(src, sslBackupFilename)
		if !file.Exists(candidate) {
			return "", fmt.Errorf("ssl backup dir %s has no %s; pass -file to a PEM backup", src, sslBackupFilename)
		}
		return candidate, nil
	}
	return src, nil
}

func (s sslStore) lastAppliedPath() (string, error) {
	uhome := file.HomeDir()
	if uhome == "" {
		return "", errors.New("home directory is unavailable")
	}
	parent := primaryBackupParent(uhome)
	if parent == "" {
		return "", fmt.Errorf("unsupported platform for ssl state: %s", runtime.GOOS)
	}
	return filepath.Join(parent, sslBackupDir, sslLastAppliedName), nil
}

func (s sslStore) recordLastAppliedFromFile(path string) error {
	sum, err := fileSHA256Sum(path)
	if err != nil {
		return err
	}
	dest, err := s.lastAppliedPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), backupDirPerms); err != nil {
		return err
	}
	return os.WriteFile(dest, []byte(sum+"\n"), 0600)
}

func (s sslStore) readLastApplied() (string, error) {
	dest, err := s.lastAppliedPath()
	if err != nil {
		return "", err
	}
	bs, err := os.ReadFile(dest)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bs)), nil
}

// warnIfDrifted prints a one-line hint when the live bundle no longer matches
// the last content trustprune wrote (typical after a macOS update restores
// Apple's cert.pem).
func (s sslStore) warnIfDrifted(w io.Writer) {
	if w == nil {
		return
	}
	path, err := s.certPath()
	if err != nil || !file.Exists(path) {
		return
	}
	want, err := s.readLastApplied()
	if err != nil || want == "" {
		return
	}
	got, err := fileSHA256Sum(path)
	if err != nil || got == want {
		return
	}
	fmt.Fprintf(w, "ssl: %s differs from the last trustprune write (SHA256 %s -> %s); a macOS update may have restored Apple's copy. Re-apply: trustprune backup -app ssl && trustprune allowlist -app ssl -file <allowlist>, or trustprune restore -app ssl\n",
		path, shortSHA(want), shortSHA(got))
}

func fileSHA256Sum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func shortSHA(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12]
}

// drifted reports whether the live bundle differs from last-applied. Exported
// for tests via the sslStore method on the concrete type.
func (s sslStore) drifted() (bool, error) {
	path, err := s.certPath()
	if err != nil {
		return false, err
	}
	want, err := s.readLastApplied()
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if want == "" {
		return false, nil
	}
	got, err := fileSHA256Sum(path)
	if err != nil {
		return false, err
	}
	return got != want, nil
}
