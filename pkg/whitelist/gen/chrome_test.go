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
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/go-sqlite/sqlite3"
)

func TestWhitelistGen__findChromeHistoryDB(t *testing.T) {
	t.Skip("TODO(adam): fix")

	db, err := findChromeHistoryDB()
	if file.Exists(`/Applications/Google Chrome.app`) {
		if err != nil {
			t.Fatal(err)
		}
		if db == nil {
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
		db, err := sqlite3.Open(cases[i].path)
		if err != nil {
			t.Fatalf("%s - err=%v", cases[i].path, err)
		}
		urls, err := getChromeUrls(db)
		if err != nil {
			t.Fatalf("store %s, err=%v", cases[i].path, err)
		}
		if len(urls) != cases[i].count {
			t.Fatalf("store: %s, got %d urls", cases[i].path, len(urls))
		}
	}
}
