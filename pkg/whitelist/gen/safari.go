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
	safariProfileLocations = []string{
		filepath.Join(file.HomeDir(), `Library/Safari/History.db`), // OSX
	}
)

func safari() ([]*url.URL, error) {
	db, err := findSafariHistoryDB()
	if err != nil {
		return nil, err
	}
	return getSafariUrls(db)
}

func getSafariUrls(db *sqlite3.DbFile) ([]*url.URL, error) {
	getter := func(rec sqlite3.Record) string {
		u, _ := rec.Values[1].(string)
		return u
	}
	return getSqliteHistoryUrls(db, "Safari", "history_items", getter)
}

func findSafariHistoryDB() (*sqlite3.DbFile, error) {
	for i := range safariProfileLocations {
		if file.Exists(safariProfileLocations[i]) {
			return sqlite3.Open(safariProfileLocations[i])
		}
	}
	return nil, errors.New("unable to find safari History.db file")
}
