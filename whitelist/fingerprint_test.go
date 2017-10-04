package whitelist

import (
	"testing"

	"github.com/adamdecaf/cert-manage/tools/_x509"
	"github.com/adamdecaf/cert-manage/tools/pem"
)

func TestWhitelist_fingerprint(t *testing.T) {
	certificates, err := pem.FromFile("../testdata/example.crt")
	if err != nil {
		t.Fatalf("error reading pem block, err=%v", err)
	}
	if len(certificates) != 1 {
		t.Fatal("Found != 1 certs in example.crt")
	}
	if certificates[0] == nil {
		t.Fatal("Unable to read cert")
	}

	wh1 := fingerprint("")
	if wh1.Matches(*certificates[0]) {
		t.Fatal("wh1 and cert shouldn't match")
	}

	wh2 := fingerprint("abc")
	if wh2.Matches(*certificates[0]) {
		t.Fatal("wh2 and cert shouldn't match")
	}

	wh3 := fingerprint("96940d99")
	if !wh3.Matches(*certificates[0]) {
		t.Fatalf("wh3='%s' and cert='%s' don't match, but should", wh3, _x509.GetHexSHA256Fingerprint(*certificates[0]))
	}

	wh4 := fingerprint("96940d991419151450d1e75f66218f6f2594e1df4af31a5ad673c9a8746817ce")
	if !wh4.Matches(*certificates[0]) {
		t.Fatal("wh4 and cert don't match, but should")
	}
}
