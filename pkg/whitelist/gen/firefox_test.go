package gen

import (
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

func TestWhitelistGen__findFirefoxPlacesFile(t *testing.T) {
	place, err := findFirefoxPlacesFile()
	if file.Exists("/Applications/Firefox.app") {
		if err != nil {
			t.Fatal(err)
		}
		if place == "" {
			t.Fatal("no error, but didn't find firefox places.sqlite")
		}
	}
}

func TestWhitelistGen__getFirefoxUrls(t *testing.T) {
	urls, err := getFirefoxUrls("../../../testdata/firefox-history.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 10 {
		t.Fatalf("got %d urls", len(urls))
	}
}
