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
