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
	"time" 
 
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
	db, err := findChromeHistoryDB() 
	if err != nil { 
		return nil, err 
	} 
	return getChromeUrls(db) 
} 
 
func getChromeUrls(db *sqlite3.DbFile) ([]*url.URL, error) { 
	getter := func(rec sqlite3.Record) *record { 
		u, _ := rec.Values[1].(string) 
 
		// parse last_visit_time 
		// "timestamp in the visit table is formatted as the number of microseconds since midnight UTC of 1 January 1601" 
		// https://digital-forensics.sans.org/blog/2010/01/21/google-chrome-forensics/ 
		w, _ := rec.Values[5].(int64) 
		when := time.Date(1601, time.January, 1, 0, 0, int(w/1e6), 0, time.UTC) 
 
		return &record{ 
			URL:        u, 
			VisistedAt: when, 
		} 
	} 
	return getSqliteHistoryUrls(db, "Chrome", "urls", getter, oldestBrowserHistoryItemDate) 
} 
 
func findChromeHistoryDB() (*sqlite3.DbFile, error) { 
	for i := range chromeProfileLocations { 
		if file.Exists(chromeProfileLocations[i]) { 
			return sqlite3.Open(chromeProfileLocations[i]) 
		} 
	} 
	return nil, errors.New("unable to find chrome History file") 
} 
