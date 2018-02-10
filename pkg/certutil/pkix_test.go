package certutil

import (
	"testing"
)

func TestCertutil__StringifyPKIXName(t *testing.T) {
	certs, err := FromFile("../../testdata/lots.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("got no certs")
	}

	answers := map[int]string{
		0: "Entrust.net, www.entrust.net/CPS_2048 incorp. by ref. (limits liab.)",
		1: "Entrust, Inc., See www.entrust.net/legal-terms",
		2: "Entrust, Inc., See www.entrust.net/legal-terms",
		3: "Entrust, Inc., www.entrust.net/CPS is incorporated by reference",
		4: "AS Sertifitseerimiskeskus",
	}

	for i := range certs {
		out := StringifyPKIXName(certs[i].Subject)
		ans := answers[i]
		if out != ans {
			t.Errorf("idx %d, got '%s'", i, out)
		}
	}
}

func TestCertutil__cleanPKIXName(t *testing.T) {
	cases := []struct {
		before, after string
	}{
		{
			// shorten double spaces
			before: "  ",
			after:  " ",
		},
		{
			before: "Google Inc",
			after:  "Google Inc",
		},
		{
			before: "AffirmTrust",
			after:  "AffirmTrust",
		},
		{
			before: "Apple Computer, Inc., Apple Computer Certificate Authority",
			after:  "Apple Computer, Inc., Apple Computer Certificate Authority",
		},
		{
			before: `Sistema Nacional de Certificacion Electronica, Superintendencia de
    Servicios de Certificacion Electronica`,
			after: "Sistema Nacional de Certificacion Electronica, Superintendencia de Servicios de Certificacion Electronica",
		},
		{
			before: `E-Tuğra EBG Bilişim Teknolojileri ve Hizmetleri A.Ş., E-Tugra Sertifikasyon
    Merkezi`,
			after: `E-Tuğra EBG Bilişim Teknolojileri ve Hizmetleri A.Ş., E-Tugra Sertifikasyon Merkezi`,
		},
		{
			before: "GeoTrust Inc., (c) 2008 GeoTrust Inc. - For authorized use only",
			after:  "GeoTrust Inc., (c) 2008 GeoTrust Inc. - For authorized use only",
		},
		{
			before: `První certifikační autorita, a.s., I.CA - Accredited Provider of Certification
    Services`,
			after: `První certifikační autorita, a.s., I.CA - Accredited Provider of Certification Services`,
		},
		{
			before: `TÜRKTRUST Bilgi İletişim ve Bilişim Güvenliği Hizmetleri A.Ş. (c)
    Aralık 2007`,
			after: `TÜRKTRUST Bilgi İletişim ve Bilişim Güvenliği Hizmetleri A.Ş. (c) Aralık 2007`,
		},
		{
			before: `NetLock Kft., Tanúsítványkiadók (Certification Services)`,
			after:  `NetLock Kft., Tanúsítványkiadók (Certification Services)`,
		},
	}

	for i := range cases {
		res := cleanPKIXName(cases[i].before)
		if res != cases[i].after {
			t.Errorf("mismatch\nResult:   %q\nExpected: %q\n", res, cases[i].after)
		}
	}
}
