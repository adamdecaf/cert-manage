package whitelist

import (
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/pem"
)

func TestWhitelist_fingerprint(t *testing.T) {
	certificates, err := pem.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatalf("error reading pem block, err=%v", err)
	}
	if len(certificates) != 1 {
		t.Fatal("Found != 1 certs in example.crt")
	}
	if certificates[0] == nil {
		t.Fatal("Unable to read cert")
	}

	fp := fingerprint("")
	if fp.Matches(*certificates[0]) {
		t.Fatal("fp and cert shouldn't match")
	}

	fp = fingerprint("abc")
	if fp.Matches(*certificates[0]) {
		t.Fatal("fp and cert shouldn't match")
	}

	fp = fingerprint("05a6db38939")
	if !fp.Matches(*certificates[0]) {
		t.Fatalf("fp='%s' and cert='%s' don't match, but should", fp, certutil.GetHexSHA256Fingerprint(*certificates[0]))
	}

	// See: https://github.com/adamdecaf/cert-manage/issues/22
	// fp = fingerprint("7e1874a98f")
	// if !fp.Matches(*certificates[0]) {
	// 	t.Fatalf("fp='%s' and cert='%s' don't match, but should", fp, certutil.GetHexSHA1Fingerprint(*certificates[0]))
	// }

	fp = fingerprint("05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030")
	if !fp.Matches(*certificates[0]) {
		t.Fatal("fp and cert don't match, but should")
	}

	// fp = fingerprint("7e1874a98faa5d6d2f506a8920ff22fbd16652d9")
	// if !fp.Matches(*certificates[0]) {
	// 	t.Fatal("fingerprint and cert don't match, but should")
	// }
}
