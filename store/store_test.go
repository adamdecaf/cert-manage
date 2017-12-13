package store

import (
	"os"
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
	dir, err = getLatestBackup("../testdata/backups/files")
	if err != nil {
		t.Error(err)
	}
	if dir != "../testdata/backups/files/lasjdaslja" {
		t.Errorf("got other backup file, dir=%s", dir)
	}

	// Latest backup from dir list
	dir, err = getLatestBackup("../testdata/backups/alpha")
	if err != nil {
		t.Error(err)
	}
	if dir != "../testdata/backups/alpha/zzzjalaj" {
		t.Errorf("got other backup dir, dir=%s", dir)
	}

	// Numeric dir list
	dir, err = getLatestBackup("../testdata/backups/numbers")
	if err != nil {
		t.Error(err)
	}
	if dir != "../testdata/backups/numbers/1513034181" {
		t.Errorf("got other backup dir, dir=%s", dir)
	}
}
