package test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/cmd"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

// high-level test of entire "gen-whitelist" code path
func TestIntegraton__genWhitelist(t *testing.T) {
	dir, err := ioutil.TempDir("", "gen-whitelist")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "whitelist.json")

	// generate whitelist
	err = cmd.GenerateWhitelist(output, "", "../testdata/file-with-urls")
	if err != nil {
		t.Fatal(err)
	}

	// read whitelist, loosely verify
	wh, err := whitelist.FromFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.Fingerprints) != 3 {
		t.Errorf("got %q", wh.Fingerprints)
	}
}
