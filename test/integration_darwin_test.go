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

package test

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/store"
)

var (
	// used to serialize _add and whitelist/restore tests
	// _add goes first, followed by whitelist/restore test,
	// but this serializes access
	darwinKeychainWG = sync.WaitGroup{}
)

func init() {
	darwinKeychainWG.Add(1)
}

func TestIntegration__date(t *testing.T) {
	cmd := Command("date", "-u", "-r", "0").Trim()
	cmd.EqualT(t, "Thu Jan  1 00:00:00 UTC 1970")

	ans := `Command:
  date -u -r 0
Output:
  Thu Jan  1 00:00:00 UTC 1970`
	if cmd.String() != ans {
		t.Errorf("cmd.String() = %q", cmd.String())
	}
}

func TestIntegration__unknown(t *testing.T) {
	cmd := CertManage("other").Trim()
	cmd.FailedT(t)
}

func TestIntegration__list(t *testing.T) {
	t.Skip("darwin support is wip")

	cmd := CertManage("list", "-count").Trim()
	cmd.CmpIntF(t, func(i int) bool { return i > 1 })
}

func TestIntegration__listFromFile(t *testing.T) {
	cmd := CertManage("list", "-file", "../testdata/lots.crt", "-count").Trim()
	cmd.CmpIntF(t, func(i int) bool { return i == 5 })
}

func TestIntegration__add(t *testing.T) {
	// don't signal we're done until this test completes
	defer darwinKeychainWG.Done()

	if !inCI() {
		t.Skip("not mutating non-CI login keychain")
	}
	setupKeychain(t)

	where := "../testdata/example.crt"
	certs, err := certutil.FromFile(where)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs", len(certs))
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	// verify cert doesn't exist already
	if inPlatformStore(t, fp) {
		name := certutil.StringifyPKIXName(certs[0].Subject)
		t.Fatalf("cert already in our store, please remove, %s", name)
	}

	// add cert and verify
	CertManage("add", "-file", where).SuccessT(t)
	if !inPlatformStore(t, fp) {
		t.Errorf("didn't find added cert, fp=%q", fp)
	}
}

func inPlatformStore(t *testing.T, fp string) bool {
	t.Helper()

	// Grab platform certs and verify ours is added
	found, err := store.Platform().List()
	if err != nil {
		t.Fatal(err)
	}
	for i := range found {
		ffp := certutil.GetHexSHA256Fingerprint(*found[i])
		if fp == ffp {
			return true
		}
	}
	return false
}

// Create a 'login.keychain' if it doesn't exist, only in CI
func setupKeychain(t *testing.T) {
	if !inCI() {
		return
	}
	t.Helper()

	// Copy our 'empty.keychain' over to the path..
	// I've tried creating it, but runnint into an error
	//
	// exec.Command("security", "create-keychain", "-p", `''`).CombinedOutput()
	//
	// The error is: 'Error exit status 255'
	// I think this is a problem where the security cli is trying to find a TTY

	where := filepath.Join(file.HomeDir(), "/Library/Keychains/login.keychain")
	if !file.Exists(where) {
		src := "../testdata/empty.keychain"
		if err := file.CopyFile(src, where); err != nil {
			t.Error(err)
		}
	}
}

// Don't run this test byitself, there's a .Wait()
// instead call `go test ... -run TestIntegration__`
func TestIntegration__WhitelistAndRemove(t *testing.T) {
	// wait until _add test finishes, so we don't clobber the keychain
	darwinKeychainWG.Wait()

	// only run if we're on CI
	if !inCI() {
		t.Skip("not mutating non-CI login keychain")
	}
	t.Helper()

	// get cert count
	certsBefore, err := store.Platform().List()
	if err != nil {
		t.Fatal(err)
	}

	// take a backup
	cmd := CertManage("backup").Trim()
	cmd.EqualT(t, "Backup completed successfully")

	// whitelist
	cmd = CertManage("whitelist", "-file", "../testdata/globalsign-whitelist.json")
	cmd.SuccessT(t)

	// verify cert count
	certsAfter, err := store.Platform().List()
	if err != nil {
		t.Fatal(err)
	}

	if len(certsBefore) <= len(certsAfter) {
		// TODO(adam): Right now .List() is just grabbing all certs, but we really should
		// try and overlap the login.keychain with system.keychain
		//
		// I thought 'security verify-cert' would do this? Flags?
		t.Fatalf("certsBefore=%d, certsAfter=%d", len(certsBefore), len(certsAfter))
	}

	// restore
	cmd = CertManage("restore").Trim()
	cmd.EqualT(t, "Restore completed successfully")

	// verify cert count
	certsAfterRestore, err := store.Platform().List()
	if err != nil {
		t.Fatal(err)
	}
	if len(certsBefore) != len(certsAfterRestore) {
		t.Fatalf("certsBefore=%d, certsAfter=%d, certsAfterRestore=%d", len(certsBefore), len(certsAfter), len(certsAfterRestore))
	}
}

// Firefox tests
// func TestIntegration__firefox(t *testing.T) {
// 	if !online(t) {
// 		t.Skip("offline, can't run firefox tests (no NSS setup)")
// 	}

// 	// Make a request using the Keychain to get it ready
// 	// travis needs this
// 	cmd := Command("timeout", strings.Split("15s firefox --headless https://google.com 2>&1 >> /var/log/firefox.log", " ")...)
// 	cmd.SuccessT(t)

// 	// Verify firefox has found certificates
// 	cmd = CertManage("list", "-app", "firefox", "-count").Trim()
// 	cmd.SuccessT(t)
// 	cmd.CmpIntF(t, func(i int) bool { return i > 1 })
// }
