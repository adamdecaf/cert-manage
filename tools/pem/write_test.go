package pem

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/adamdecaf/cert-manage/tools/_x509"
)

func TestPEM__write(t *testing.T) {
	c1, err := FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	// write that back, then read it again and compare
	f, err := ioutil.TempFile("", "cert-manage")
	// f, err := os.Create("cert-mange-pem")
	if err != nil {
		t.Fatal(err)
	}
	err = os.Chmod(f.Name(), 0666)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	// write
	err = ToFile(f.Name(), c1)
	if err != nil {
		t.Fatal(err)
	}

	// read the written certs back and compare
	c2, err := FromFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(c1) != len(c2) {
		t.Fatalf("len(c1)=%d != len(c2)=%d", len(c1), len(c2))
	}
	for i := range c1 {
		if c1 == nil || c2 == nil {
			t.Fatalf("either c1 or c2 are null\nc1=%v\nc2=%v", c1, c2)
		}
		f1 := _x509.GetHexSHA256Fingerprint(*c1[i])
		f2 := _x509.GetHexSHA256Fingerprint(*c2[i])
		if f1 != f2 {
			t.Fatalf("f1='%s' != f2='%s'", f1, f2)
		}
	}
}
