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
	"os"
	"path/filepath"
	"testing"
)

func TestStore__getCertManageDir(t *testing.T) {
	name := "test-getCertManageDir"
	d1, err := getCertManageDir(name)
	if err != nil {
		t.Error(err)
	}

	// make the dir again just to make sure everything is ok
	d2, err := getCertManageDir(name)
	if err != nil {
		t.Error(err)
	}

	if d1 != d2 {
		t.Errorf("%s != %s", d1, d2)
	}
	defer os.Remove(d1)

	// If we're asking for an abs reference just return that.
	// AKA. Don't append getCertManageParentDir()
	dir, err := filepath.Abs("../../testdata/backups/files")
	if err != nil {
		t.Error(err)
	}
	_, err = os.Stat(dir) // make sure `dir` exists
	if err != nil {
		t.Error(err)
	}
	d3, err := getCertManageDir(dir)
	if err != nil {
		t.Error(err)
	}
	if dir != d3 {
		t.Errorf("dir=%s != d3=%s", dir, d3)
	}
	_, err = os.Stat(dir) // make sure `dir` exists
	if err != nil {
		t.Error(err)
	}
}

func TestStore__getCertManageDirNeg(t *testing.T) {
	// Grab a file and ensure it can't be modified
	f, err := filepath.Abs("../../main.go")
	if err != nil {
		t.Error(err)
	}
	s, err := os.Stat(f)
	if err != nil {
		t.Error(err)
	}

	// "get dir"
	dir, err := getCertManageDir(f)
	if err == nil {
		t.Errorf("expected error, dir=%s", dir)
	}
	s2, err := os.Stat(f)
	if err != nil {
		t.Error(err)
	}
	if s.Mode().String() != s2.Mode().String() {
		t.Errorf("s.Mode()=%s != s2.Mode()=%s", s.Mode().String(), s2.Mode().String())
	}
}

func TestStore__getLatestBackup(t *testing.T) {
	// return an error if the dir doesn't exist
	dir, err := getLatestBackup("missing")
	if err == nil {
		t.Errorf("expected error, got dir=%s, err=%v", dir, err)
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected IsNotExist, got err=%v", err)
	}
	if dir != "" {
		t.Errorf("expected empty dir, dir=%s", dir)
	}

	// Get latest backup from dir of files
	dir, err = getLatestBackup("../../testdata/backups/files")
	if err != nil {
		t.Error(err)
	}
	if dir != "../../testdata/backups/files/lasjdaslja" {
		t.Errorf("got other backup file, dir=%s", dir)
	}

	// Latest backup from dir list
	dir, err = getLatestBackup("../../testdata/backups/alpha")
	if err != nil {
		t.Error(err)
	}
	if dir != "../../testdata/backups/alpha/zzzjalaj" {
		t.Errorf("got other backup dir, dir=%s", dir)
	}

	// Numeric dir list
	dir, err = getLatestBackup("../../testdata/backups/numbers")
	if err != nil {
		t.Error(err)
	}
	if dir != "../../testdata/backups/numbers/1513034181" {
		t.Errorf("got other backup dir, dir=%s", dir)
	}
}
