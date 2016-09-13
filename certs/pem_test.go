package certs

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestReadSinglePEMBlock(t *testing.T) {
	r, err := os.Open("../testdata/example.crt")
	defer r.Close()
	if err != nil {
		t.Fatal(err)
	}

	body, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	certificates, err := ParsePEMIntoCerts(body)
	if err != nil {
		t.Fatal(err)
	}

	if len(certificates) != 1 {
		t.Fatal("Found != 1 certs in example.crt")
	}

	// match a field on the cert
	crls := certificates[0].CRLDistributionPoints
	if len(crls) != 1 {
		t.Fatal("Found != 1 crls in example.crt")
	}
	if crls[0] != "http://certificates.starfieldtech.com/repository/sfroot.crl" {
		t.Fatalf("found other crl(s) (%s) in example.crt", crls)
	}
}
