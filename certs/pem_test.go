package certs

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"testing"
)

func loadPEM(t *testing.T, path string) []*x509.Certificate {
	r, err := os.Open(path)
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
	return certificates
}

func TestReadSinglePEMBlock(t *testing.T) {
	certificates := loadPEM(t, "../testdata/example.crt")
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

func TestReadLotsOfPEMBlock(t *testing.T) {
	certificates := loadPEM(t, "../testdata/lots.crt")
	if len(certificates) != 5 {
		t.Fatal("Found != 5 certs in example.crt")
	}
}
