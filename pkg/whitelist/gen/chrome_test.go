package gen

import (
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

func TestWhitelistGen__findChromeHistoryFile(t *testing.T) {
	hist, err := findChromeHistoryFile()
	if file.Exists(`/Applications/Google Chrome.app`) {
		if err != nil {
			t.Fatal(err)
		}
		if hist == "" {
			t.Fatal("no error, but didn't find chrome History")
		}
	}
}

func TestWhitelistGen__getChromeUrls(t *testing.T) {
	urls, err := getChromeUrls("../../../testdata/chrome-history.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 3 {
		t.Fatalf("got %d urls", len(urls))
	}
}
