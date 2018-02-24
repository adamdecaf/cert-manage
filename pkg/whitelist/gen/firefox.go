// Copyright 2018 Adam Shannon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gen

import (
	"errors"
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
	db, err := findFirefoxPlacesDB()
	if err != nil {
		return nil, err
	}
	return getFirefoxUrls(db)
}

func getFirefoxUrls(db *sqlite3.DbFile) ([]*url.URL, error) {
	getter := func(rec sqlite3.Record) string {
		u, _ := rec.Values[1].(string)
		return u
	}
	return getSqliteHistoryUrls(db, "Firefox", "moz_places", getter)
}

func findFirefoxPlacesDB() (*sqlite3.DbFile, error) {
	// Paths are globs, so check each match
	for i := range firefoxProfileLocations {
		matches, err := filepath.Glob(firefoxProfileLocations[i])
		if err != nil {
			return nil, err
		}
		for j := range matches {
			if file.Exists(matches[j]) {
				return sqlite3.Open(matches[j])
			}
		}
	}
	return nil, errors.New("unable to find firefox places.sqlite")
}
