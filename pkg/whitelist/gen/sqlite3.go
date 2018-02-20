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
	"fmt"
	"net/url"

	"github.com/go-sqlite/sqlite3"
)

// urlGetter grabs a sqlite record and returns the url
// this varies from table to table (browser history impl)
type urlGetter func(sqlite3.Record) string

// getSqliteHistoryUrls
func getSqliteHistoryUrls(db *sqlite3.DbFile, name, table string, getter urlGetter) ([]*url.URL, error) {
	var acc []*url.URL
	err := db.VisitTableRecords(table, func(rowId *int64, rec sqlite3.Record) error {
		if rowId == nil {
			return fmt.Errorf("unexpected nil RowID in %s sqlite database", name)
		}

		raw := getter(rec)
		if raw == "" && debug {
			fmt.Printf("whitelist/gen: (%s) unknown rec.Values[1], %v\n", name, rec.Values[1])
		}
		parsed, err := url.Parse(raw)
		if err == nil {
			acc = append(acc, parsed)
		}
		if err != nil && debug {
			fmt.Printf("whitelist/gen: (%s) error parsing %q, err=%v\n", name, parsed, err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return acc, nil
}
