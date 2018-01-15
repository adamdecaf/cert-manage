package whitelist

import (
	"os"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/pem"
)

func TestWhitelist_nocert(t *testing.T) {
	wh1 := Whitelist{}
	wh2 := Whitelist{
		fingerprints: []item{fingerprint("a")},
	}

	if wh1.Matches(nil) {
		t.Fatalf("shouldn't have matched, empty whitelist")
	}
	if wh2.Matches(nil) {
		t.Fatalf("shouldn't have matched, empty whitelist")
	}
}

func TestWhitelist_emptywhitelist(t *testing.T) {
	wh := Whitelist{}
	certs, err := pem.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	for i := range certs {
		if wh.Matches(certs[i]) {
			t.Fatalf("err, empty whitelist shouldn't match")
		}
	}
}

func TestWhitelist_remove(t *testing.T) {
	certs, err := pem.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	wh := Whitelist{
		fingerprints: []item{fingerprint("05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030")},
	}

	for i := range certs {
		if !wh.Matches(certs[i]) {
			t.Fatalf("error, should have matched")
		}
	}
}

func TestWhitelist__file(t *testing.T) {
	wh, err := FromFile("../../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.fingerprints) != 1 {
		t.Fatalf("Wrong number of parsed fingerprints in whitelist, found=%d", len(wh.fingerprints))
	}

	for _, i := range wh.fingerprints {
		if v, ok := i.(fingerprint); ok && v.String() != "a" {
			t.Fatalf("Fingerprint didn't match, got %s", v)
		}
	}
}

func TestWhitelist__emptyfile(t *testing.T) {
	wh, err := FromFile("../../testdata/empty-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.fingerprints) != 0 {
		t.Fatalf("empty whitelist was not parsed as empty! had %d fingerprints", len(wh.fingerprints))
	}
}

func TestWhitelist_filecycle(t *testing.T) {
	wh, err := FromFile("../../testdata/complete-whitelist.json")
	wh.fingerprints = []item{} // TODO(adam): `Whitelist` needs a redo
	if err != nil {
		t.Fatal(err)
	}
	where := "../../test-whitelist.json"
	defer os.Remove(where)
	if err = ToFile(where, wh); err != nil {
		t.Fatal(err)
	}
	wh2, err := FromFile(where)
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.fingerprints) != len(wh2.fingerprints) {
		t.Errorf("%d != %d", len(wh.fingerprints), len(wh2.fingerprints))
	}
}
