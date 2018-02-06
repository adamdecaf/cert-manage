package store

import (
	"os/exec"
	"testing"
)

func TestStoreOpenSSL__paths(t *testing.T) {
	err := exec.Command("which openssl").Run()
	if err != nil {
		t.Skipf("can't find openssl, err=%v", err)
	}

	st := opensslStore{}
	dir, err := st.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if dir == "" {
		t.Error("empty dir")
	}
}
