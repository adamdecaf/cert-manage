package gen

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/go-sqlite/sqlite3"
)

var (
	chromeProfileLocations = []string{
		filepath.Join(file.HomeDir(), `/Library/Application Support/Google/Chrome/Default/History`), // OSX not signed in
		// C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Preferences // TODO
	}
)

func chrome() ([]*url.URL, error) {
	history, err := findChromeHistoryFile()
	if err != nil {
		return nil, err
	}
	return getChromeUrls(history)
}

func findChromeHistoryFile() (string, error) {
	for i := range chromeProfileLocations {
		if file.Exists(chromeProfileLocations[i]) {
			return chromeProfileLocations[i], nil
		}
	}
	return "", errors.New("unable to find chrome History file")
}

func getChromeUrls(placesPath string) ([]*url.URL, error) {
	db, err := sqlite3.Open(placesPath)
	if err != nil {
		return nil, err
	}

	var acc []*url.URL
	err = db.VisitTableRecords("urls", func(rowId *int64, rec sqlite3.Record) error {
		if rowId == nil {
			return fmt.Errorf("unexpected nil RowID in Chrome sqlite database")
		}

		u, ok := rec.Values[1].(string)
		if !ok && debug {
			fmt.Printf("whitelist/gen: (chrome) unknown rec.Values[1], %v\n", rec.Values[1])
		}
		parsed, err := url.Parse(u)
		if err == nil {
			acc = append(acc, parsed)
		}
		if err != nil && debug {
			fmt.Printf("whitelist/gen: (chrome) error parsing %q, err=%v\n", u, err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return acc, nil
}
