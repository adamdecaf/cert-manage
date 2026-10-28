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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const dockerJavaImage = "eclipse-temurin:21-jdk-jammy"

// tempJavaHomeWithCacerts builds a throwaway JAVA_HOME whose cacerts file is a
// real keystore. The keystore is created with keytool when it is on PATH, or
// with docker running keytool (falling back to copying the image cacerts).
// The host JDK is never read or written.
func tempJavaHomeWithCacerts(t *testing.T) string {
	t.Helper()

	tmp := t.TempDir()
	sec := filepath.Join(tmp, "lib", "security")
	if err := os.MkdirAll(sec, 0755); err != nil {
		t.Fatal(err)
	}
	cacerts := filepath.Join(sec, "cacerts")
	refuseSystemKeystore(t, cacerts)

	example := filepath.Join("..", "..", "testdata", "example.crt")
	if _, err := os.Stat(example); err != nil {
		t.Fatalf("testdata example.crt: %v", err)
	}

	var errs []string
	if bin, err := exec.LookPath("keytool"); err != nil {
		errs = append(errs, "keytool not on PATH")
	} else if err := importCertWithKeytool(bin, example, cacerts); err != nil {
		errs = append(errs, fmt.Sprintf("local keytool: %v", err))
	} else {
		assertWritableNonEmptyCacerts(t, cacerts)
		return tmp
	}

	if err := createCacertsWithDocker(t, tmp, example, cacerts); err != nil {
		errs = append(errs, err.Error())
		t.Skipf("cannot create a temp Java cacerts keystore: %s", strings.Join(errs, "; "))
	}
	assertWritableNonEmptyCacerts(t, cacerts)
	return tmp
}

func importCertWithKeytool(keytoolBin, exampleCrt, cacertsPath string) error {
	cmd := exec.Command(keytoolBin,
		"-importcert", "-noprompt", "-alias", "example",
		"-file", exampleCrt,
		"-keystore", cacertsPath,
		"-storepass", defaultKeystorePassword,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func createCacertsWithDocker(t *testing.T, javaHome, exampleCrt, cacertsPath string) error {
	t.Helper()

	docker, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker not on PATH: %v", err)
	}

	absHome, err := filepath.Abs(javaHome)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(exampleCrt)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(absHome, "example.crt"), b, 0644); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	args := []string{"run", "--rm"}
	if uid := os.Getuid(); uid >= 0 {
		args = append(args, "--user", fmt.Sprintf("%d:%d", uid, os.Getgid()))
	}
	args = append(args,
		"-v", absHome+":/work",
		dockerJavaImage,
		"keytool", "-importcert", "-noprompt", "-alias", "example",
		"-file", "/work/example.crt",
		"-keystore", "/work/lib/security/cacerts",
		"-storepass", defaultKeystorePassword,
	)
	out, err := exec.CommandContext(ctx, docker, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	_ = os.Remove(cacertsPath)
	keytoolErr := fmt.Errorf("docker keytool: %v: %s", err, bytes.TrimSpace(out))

	// Copy the image cacerts through stdout so the file is owned by this user
	// (a bind-mounted copy would often be root-owned and trip SudoCopyFile).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel2()
	cat := exec.CommandContext(ctx2, docker, "run", "--rm", dockerJavaImage,
		"bash", "-c", `cat "$JAVA_HOME/lib/security/cacerts"`)
	var stdout, stderr bytes.Buffer
	cat.Stdout = &stdout
	cat.Stderr = &stderr
	if err := cat.Run(); err != nil {
		return fmt.Errorf("%v; docker cat cacerts: %v: %s", keytoolErr, err, bytes.TrimSpace(stderr.Bytes()))
	}
	if stdout.Len() == 0 {
		return fmt.Errorf("%v; docker cat cacerts: empty output", keytoolErr)
	}
	if err := os.WriteFile(cacertsPath, stdout.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

func assertWritableNonEmptyCacerts(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cacerts stat: %v", err)
	}
	if st.Size() == 0 {
		t.Fatalf("cacerts at %s is empty", path)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("temp cacerts must be writable by the current user so Restore uses CopyFile, not sudo: %v", err)
	}
	f.Close()
}

func refuseIfOutside(t *testing.T, root, path, what string) {
	t.Helper()
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("refusing to use %s path %s outside %s", what, path, root)
	}
}

func refuseSystemKeystore(t *testing.T, path string) {
	t.Helper()
	cleaned := filepath.Clean(path)
	prefixes := []string{
		"/usr/lib/jvm",
		"/usr/java",
		"/Library/Java",
		"/System/Library/Java",
		"/etc/ssl/certs/java",
		"/etc/pki",
	}
	for _, p := range prefixes {
		if cleaned == p || strings.HasPrefix(cleaned, p+string(os.PathSeparator)) {
			t.Fatalf("refusing to run against system keystore path %s", path)
		}
	}
}

// javaBackupTestEnv points package-level ktool at a temp JAVA_HOME and HOME
// so Backup/Restore never touch the host JDK or the real backup directory.
func javaBackupTestEnv(t *testing.T) (javaStore, string) {
	t.Helper()

	javaHome := tempJavaHomeWithCacerts(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("JAVA_HOME", javaHome)

	orig := ktool
	t.Cleanup(func() { ktool = orig })
	ktool = keytool{
		javahome:         javaHome,
		javaInstallPaths: nil,
		// Use a relative path (no leading slash). Production linux/darwin
		// relativeKeystorePaths are "/lib/security/cacerts"-style; on older
		// Go, filepath.Join treated those as absolute and dropped javahome.
		// Go 1.27 keeps the home prefix either way; stay relative for clarity.
		relativeKeystorePaths: []string{"lib/security/cacerts"},
	}

	kpath, err := ktool.getKeystorePath()
	if err != nil {
		t.Fatalf("getKeystorePath: %v", err)
	}
	refuseIfOutside(t, javaHome, kpath, "keystore")
	refuseSystemKeystore(t, kpath)

	backupDir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		t.Fatalf("getCertManageDir: %v", err)
	}
	refuseIfOutside(t, home, backupDir, "backup dir")

	return javaStore{}, kpath
}

func TestJavaBackupRestoreRoundTrip(t *testing.T) {
	s, kpath := javaBackupTestEnv(t)

	original, err := os.ReadFile(kpath)
	if err != nil {
		t.Fatal(err)
	}
	if len(original) == 0 {
		t.Fatal("snapshot of live cacerts is empty")
	}

	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil {
		t.Fatalf("GetLatestBackup: %v", err)
	}
	if latest == "" {
		t.Fatal("GetLatestBackup returned empty path")
	}
	st, err := os.Stat(latest)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if st.IsDir() {
		t.Fatalf("latest backup %s is a directory, want file", latest)
	}
	backed, err := os.ReadFile(latest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backed, original) {
		t.Fatalf("backup is not a complete copy: got %d bytes, want %d", len(backed), len(original))
	}

	marker := []byte("MUTATED-JAVA-CACERTS-" + t.Name() + "\n")
	if err := os.WriteFile(kpath, marker, 0644); err != nil {
		t.Fatal(err)
	}
	mutated, err := os.ReadFile(kpath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mutated, original) {
		t.Fatal("mutation did not change live cacerts bytes")
	}

	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, err := os.ReadFile(kpath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("live cacerts after Restore does not match original snapshot: got %d bytes, want %d", len(got), len(original))
	}
}

func TestJavaRestore_IgnoresWherePath(t *testing.T) {
	// TODO: javaStore.Restore ignores its `where` argument and always
	// restores from GetLatestBackup(). The CLI -file flag is plumbed from
	// main.go through cmd.RestoreForApp into Store.Restore, but
	// javaStore.Restore never reads the argument.
	s, kpath := javaBackupTestEnv(t)

	original, err := os.ReadFile(kpath)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}

	if err := os.WriteFile(kpath, []byte("MUTATED-BEFORE-RESTORE-WHERE\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alternate := filepath.Join(t.TempDir(), "alternate-java.bck")
	altBytes := []byte("ALTERNATE-JAVA-BACKUP-MARKER\n")
	if err := os.WriteFile(alternate, altBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if alternate == latest {
		t.Fatal("alternate path unexpectedly equals latest backup")
	}

	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore(alternate): %v", err)
	}

	got, err := os.ReadFile(kpath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, altBytes) {
		t.Error("Restore used the `where` path; javaStore.Restore currently ignores it and restores GetLatestBackup()")
	}
	if !bytes.Equal(got, original) {
		t.Errorf("live cacerts does not match original snapshot after Restore(where)")
	}
	latestBytes, err := os.ReadFile(latest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, latestBytes) {
		t.Errorf("live cacerts does not match GetLatestBackup() contents")
	}
}
