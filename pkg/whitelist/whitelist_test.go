package whitelist

import (
	"os"
	"reflect"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/pem"
)

func TestWhitelist_nocert(t *testing.T) {
	wh1 := Whitelist{}
	wh2 := Whitelist{
		Fingerprints: []string{"a"},
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
		Fingerprints: []string{
			"05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030",
		},
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
	if len(wh.Fingerprints) != 1 {
		t.Errorf("Wrong number of parsed fingerprints in whitelist, found=%d", len(wh.Fingerprints))
	}

	if !reflect.DeepEqual(wh.Fingerprints, []string{"a"}) {
		t.Errorf("got %q", wh.Fingerprints)
	}
}

func TestWhitelist__emptyfile(t *testing.T) {
	wh, err := FromFile("../../testdata/empty-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.Fingerprints) != 0 {
		t.Fatalf("empty whitelist was not parsed as empty! had %d fingerprints", len(wh.Fingerprints))
	}
}

func TestWhitelist_filecycle(t *testing.T) {
	wh, err := FromFile("../../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	where := "../../test-whitelist.json"
	defer os.Remove(where)
	if err = wh.ToFile(where); err != nil {
		t.Fatal(err)
	}
	wh2, err := FromFile(where)
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.Fingerprints) != len(wh2.Fingerprints) {
		t.Errorf("%d != %d", len(wh.Fingerprints), len(wh2.Fingerprints))
	}
}

func TestWhitlist__matching(t *testing.T) {
	certificates, err := pem.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 1 {
		t.Errorf("got %d certs", len(certificates))
	}
	if certificates[0] == nil {
		t.Error("Unable to read first cert")
	}

	wh := Whitelist{}
	if wh.Matches(certificates[0]) {
		t.Error("empty whitelist and cert shouldn't match")
	}

	wh.Fingerprints = []string{"abc"}
	if wh.Matches(certificates[0]) {
		t.Error("shouldn't match")
	}

	wh.Fingerprints = []string{"05a6db38939"}
	if wh.Matches(certificates[0]) {
		t.Errorf("%q shouldn't mattch, (short fingerprints not allowed)", wh.Fingerprints)
	}

	wh.Fingerprints = []string{"05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030"}
	if !wh.Matches(certificates[0]) {
		t.Error("should have matched")
	}
}
