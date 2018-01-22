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
	firefoxProfileLocations = []string{
		filepath.Join(file.HomeDir(), "/Library/Application Support/Firefox/Profiles/*/places.sqlite"), // OSX
		// C:\Users\%USERNAME%\AppData\Roaming\Mozilla\Firefox\Profiles\%PROFILE%.default\places.sqlite // TODO
	}
)

func firefox() ([]*url.URL, error) {
	places, err := findFirefoxPlacesFile()
	if err != nil {
		return nil, err
	}
	return getFirefoxUrls(places)
}

func findFirefoxPlacesFile() (string, error) {
	// Paths are globs, so check each match
	for i := range firefoxProfileLocations {
		matches, err := filepath.Glob(firefoxProfileLocations[i])
		if err != nil {
			return "", err
		}
		for j := range matches {
			if file.Exists(matches[j]) {
				return matches[j], nil
			}
		}
	}
	return "", errors.New("unable to find firefox places.sqlite")
}

func getFirefoxUrls(placesPath string) ([]*url.URL, error) {
	db, err := sqlite3.Open(placesPath)
	if err != nil {
		return nil, err
	}

	var acc []*url.URL
	err = db.VisitTableRecords("moz_places", func(rowId *int64, rec sqlite3.Record) error {
		if rowId == nil {
			return fmt.Errorf("unexpected nil RowID in Firefox sqlite database")
		}

		u, ok := rec.Values[1].(string)
		if !ok && debug {
			fmt.Printf("whitelist/gen: (firefox) unknown rec.Values[1], %v\n", rec.Values[1])
		}
		parsed, err := url.Parse(u)
		if err == nil {
			acc = append(acc, parsed)
		}
		if err != nil && debug {
			fmt.Printf("whitelist/gen: (firefox) error parsing %q, err=%v\n", u, err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return acc, nil
}
