package certutil

import (
	"compress/gzip"
	"io/ioutil"
	"os"
	"testing"
)

func TestCertUtil__decodePEM(t *testing.T) {
	bs, err := ioutil.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d", len(certs))
	}
}

func TestCertUtil__decodeNSS(t *testing.T) {
	f, err := os.Open("../../testdata/certdata.txt.gz")
	if err != nil {
		t.Fatal(err)
	}
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 133 {
		t.Errorf("got %d", len(certs))
	}
}
