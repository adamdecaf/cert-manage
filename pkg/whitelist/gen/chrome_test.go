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
	cases := []struct {
		count int
		path  string
	}{
		{
			count: 3,
			path:  "../../../testdata/chrome-history.sqlite",
		},
		{
			count: 8,
			path:  "../../../testdata/chrome-history-win.sqlite",
		},
	}
	for i := range cases {
		urls, err := getChromeUrls(cases[i].path)
		if err != nil {
			t.Fatalf("store %s, err=%v", cases[i].path, err)
		}
		if len(urls) != cases[i].count {
			t.Fatalf("store: %s, got %d urls", cases[i].path, len(urls))
		}
	}
}
