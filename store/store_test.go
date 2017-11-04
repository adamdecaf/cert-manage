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
