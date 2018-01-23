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
	cases := []struct {
		count int
		path  string
	}{
		{
			count: 10,
			path:  "../../../testdata/firefox-history.sqlite",
		},
		{
			count: 10,
			path:  "../../../testdata/firefox-history-win.sqlite",
		},
	}
	for i := range cases {
		urls, err := getFirefoxUrls(cases[i].path)
		if err != nil {
			t.Fatalf("store %s, err=%v", cases[i].path, err)
		}
		if len(urls) != cases[i].count {
			t.Fatalf("store: %s, got %d urls", cases[i].path, len(urls))
		}
	}
}
