package certs

import (
	"testing"
	"time"
)

func TestWhitelist_HexSignature(t *testing.T) {
	certificates := loadPEM(t, "../testdata/example.crt")
	if len(certificates) != 1 {
		t.Fatal("Found != 1 certs in example.crt")
	}
	if certificates[0] == nil {
		t.Fatal("Unable to read cert")
	}

	// Empty signature
	wh1 := HexSignatureWhitelistItem{
		Signature: "",
	}
	if wh1.Matches(*certificates[0]) {
		t.Fatal("wh1 and cert shouldn't match")
	}

	// Signature too short
	wh2 := HexSignatureWhitelistItem{
		Signature: "",
	}
	if wh2.Matches(*certificates[0]) {
		t.Fatal("wh2 and cert shouldn't match")
	}

	// Short signature
	wh3 := HexSignatureWhitelistItem{
		Signature: "96940d99",
	}
	if !wh3.Matches(*certificates[0]) {
		t.Fatal("wh3 and cert don't match, but should")
	}

	// Full signature
	wh4 := HexSignatureWhitelistItem{
		Signature: "96940d991419151450d1e75f66218f6f2594e1df4af31a5ad673c9a8746817ce",
	}
	if !wh4.Matches(*certificates[0]) {
		t.Fatal("wh4 and cert don't match, but should")
	}
}

func TestWhitelist_IssuerCommonName(t *testing.T) {
	certificates := loadPEM(t, "../testdata/example.crt")
	if len(certificates) != 1 {
		t.Fatal("Found != 1 certs in example.crt")
	}
	if certificates[0] == nil {
		t.Fatal("Unable to read cert")
	}

	// Empty whitelist name
	wh1 := IssuersCommonNameWhitelistItem{
		Name: "",
	}
	if wh1.Matches(*certificates[0]) {
		t.Fatal("wh1 and cert should not match")
	}

	// Matching word
	wh2 := IssuersCommonNameWhitelistItem{
		Name: "Starfield",
	}
	if !wh2.Matches(*certificates[0]) {
		t.Fatal("wh2 and cert don't match")
	}

	// Full Match
	wh3 := IssuersCommonNameWhitelistItem{
		Name: "Starfield Secure Certification Authority",
	}
	if !wh3.Matches(*certificates[0]) {
		t.Fatal("wh3 and cert don't match")
	}
}

func TestWhitelist_NotAfter(t *testing.T) {
	certificates := loadPEM(t, "../testdata/example.crt")
	if len(certificates) != 1 {
		t.Fatal("Found != 1 certs in example.crt")
	}
	if certificates[0] == nil {
		t.Fatal("Unable to read cert")
	}

	// Whitelist NotAfter is before cert's NotAfter
	t1, _ := time.Parse("2006-01-02 03:04:05 -0700 MST", "2006-11-16 01:15:40 +0000 UTC")
	wh1 := NotAfterWhitelistItem{
		Time: t1,
	}
	if wh1.Matches(*certificates[0]) {
		t.Fatal("wh1 has a NotAfter before cert, it should not be whitelisted")
	}

	// Whitelist NotAfter is equal to cert's NotAfter
	t2, _ := time.Parse("2006-01-02 03:04:05 -0700 MST", "2026-11-16 01:15:40 +0000 UTC")
	wh2 := NotAfterWhitelistItem{
		Time: t2,
	}
	if !wh2.Matches(*certificates[0]) {
		t.Fatal("wh2 and cert should match on NotAfter")
	}

	// Whitelist NotAfter is after cert's NotAfter
	t3, _ := time.Parse("2006-01-02 03:04:05 -0700 MST", "2036-11-16 01:15:40 +0000 UTC")
	wh3 := NotAfterWhitelistItem{
		Time: t3,
	}
	if !wh3.Matches(*certificates[0]) {
		t.Fatal("wh3 should allow the cert through, it's NotAfter is later than the cert")
	}
}

func TestWhitelist__FromFileFull(t *testing.T) {
	items, err := FromFile("../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("Wrong number of parsed items in whitelist, found=%d", len(items))
	}

	for _,i := range items {
		if v,ok := i.(HexSignatureWhitelistItem); ok && v.Signature != "a" {
			t.Fatalf("Signature didn't match, got %s", v.Signature)
		}
		if v,ok := i.(IssuersCommonNameWhitelistItem); ok && v.Name != "b" {
			t.Fatalf("Issuer Name didn't match, got %s", v.Name)
		}
		when, _ := time.Parse(NotAfterFormat, "2016-01-01 12:34:56")
		if v,ok := i.(NotAfterWhitelistItem); ok && !v.Time.Equal(when) {
			t.Fatalf("NotAfter times don't match, got %s", v.Time)
		}
	}
}

func TestWhitelist__FromFileEmpty(t *testing.T) {
	items, err := FromFile("../testdata/empty-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("empty whitelist was not parsed as empty! had %d items", len(items))
	}
}
