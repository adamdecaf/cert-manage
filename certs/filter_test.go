package certs

import (
	"testing"
)

func TestFilter_EmptyIncoming(t *testing.T) {
	wh := []WhitelistItem{HexSignatureWhitelistItem{Signature: "a"}}

	if removable := Filter(nil, nil); len(removable) != 0 {
		t.Fatalf("found %d removable certs, expected 0", len(removable))
	}
	if removable := Filter(nil, wh); len(removable) != 0 {
		t.Fatalf("found %d removable certs, expected 0", len(removable))
	}
}

func TestFilter_EmptyWhitelist(t *testing.T) {
	certificates := loadPEM(t, "../testdata/example.crt")
	removable := Filter(certificates, nil)
	if len(removable) != 1 {
		t.Fatalf("found %d removable certs, expected 1", len(removable))
	}
}

func TestFilter_Remove(t *testing.T) {
	certificates := loadPEM(t, "../testdata/example.crt")
	signature := "96940d991419151450d1e75f66218f6f2594e1df4af31a5ad673c9a8746817ce"

	wh := []WhitelistItem{HexSignatureWhitelistItem{Signature: signature}}

	if removable := Filter(certificates, wh); len(removable) != 0 {
		t.Fatalf("found %d removable certs, expected 0", len(removable))
	}
}
