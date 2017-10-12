package whitelist

import (
	"testing"

	"github.com/adamdecaf/cert-manage/tools/pem"
)

func TestWhitelist_nocerts(t *testing.T) {
	wh := []item{fingerprint("a")}

	if removable := Removable(nil, nil); len(removable) != 0 {
		t.Fatalf("found %d removable certs, expected 0", len(removable))
	}
	if removable := Removable(nil, wh); len(removable) != 0 {
		t.Fatalf("found %d removable certs, expected 0", len(removable))
	}
}

func TestWhitelist_emptywhitelist(t *testing.T) {
	certificates, err := pem.FromFile("../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	removable := Removable(certificates, nil)
	if len(removable) != 1 {
		t.Fatalf("found %d removable certs, expected 1", len(removable))
	}
}

func TestWhitelist_remove(t *testing.T) {
	certificates, err := pem.FromFile("../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	wh := []item{fingerprint("96940d991419151450d1e75f66218f6f2594e1df4af31a5ad673c9a8746817ce")}

	if removable := Removable(certificates, wh); len(removable) != 0 {
		t.Fatalf("found %d removable certs, expected 0", len(removable))
	}
}

func TestWhitelist__file(t *testing.T) {
	items, err := FromFile("../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("Wrong number of parsed items in whitelist, found=%d", len(items))
	}

	for _, i := range items {
		if v, ok := i.(fingerprint); ok && v.String() != "a" {
			t.Fatalf("Fingerprint didn't match, got %s", v)
		}
	}
}

func TestWhitelist__emptyfile(t *testing.T) {
	items, err := FromFile("../testdata/empty-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("empty whitelist was not parsed as empty! had %d items", len(items))
	}
}
