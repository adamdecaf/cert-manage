package whitelist

import (
	"testing"

	"github.com/adamdecaf/cert-manage/tools/pem"
)

func TestWhitelist_nocerts(t *testing.T) {
	wh := []item{fingerprint{Signature: "a"}}

	if removable := findRemovable(nil, nil); len(removable) != 0 {
		t.Fatalf("found %d removable certs, expected 0", len(removable))
	}
	if removable := findRemovable(nil, wh); len(removable) != 0 {
		t.Fatalf("found %d removable certs, expected 0", len(removable))
	}
}

func TestWhitelist_emptywhitelist(t *testing.T) {
	certificates, err := pem.FromFile("../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	removable := findRemovable(certificates, nil)
	if len(removable) != 1 {
		t.Fatalf("found %d removable certs, expected 1", len(removable))
	}
}

func TestWhitelist_remove(t *testing.T) {
	certificates, err := pem.FromFile("../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	signature := "96940d991419151450d1e75f66218f6f2594e1df4af31a5ad673c9a8746817ce"

	wh := []item{fingerprint{Signature: signature}}

	if removable := findRemovable(certificates, wh); len(removable) != 0 {
		t.Fatalf("found %d removable certs, expected 0", len(removable))
	}
}

func TestWhitelist__file(t *testing.T) {
	items, err := loadFromFile("../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("Wrong number of parsed items in whitelist, found=%d", len(items))
	}

	for _, i := range items {
		if v, ok := i.(fingerprint); ok && v.Signature != "a" {
			t.Fatalf("Signature didn't match, got %s", v.Signature)
		}
	}
}

func TestWhitelist__emptyfile(t *testing.T) {
	items, err := loadFromFile("../testdata/empty-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("empty whitelist was not parsed as empty! had %d items", len(items))
	}
}
