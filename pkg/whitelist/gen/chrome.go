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
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/go-sqlite/sqlite3"
)

var (
	chromeProfileLocations = []string{
		filepath.Join(file.HomeDir(), `/Library/Application Support/Google/Chrome/Default/History`), // OSX not signed in
		// TODO(adam):
		// Linux: /home/$USER/.config/google-chrome/
		// Linux: /home/$USER/.config/chromium/
		// Windows Vista (and Win 7): C:\Users\[USERNAME]\AppData\Local\Google\Chrome\
		// Windows XP: C:\Documents and Settings\[USERNAME]\Local Settings\Application Data\Google\Chrome\
		// Win 8+: C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Preferences
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
