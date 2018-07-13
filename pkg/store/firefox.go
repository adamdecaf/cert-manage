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

package store

import (
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

var (
	firefoxProfileSuggestions = []string{
		filepath.Join(file.HomeDir(), ".mozilla/firefox/*.default"),                              // Ubuntu
		filepath.Join(file.HomeDir(), "/Library/Application Support/Firefox/Profiles/*.default"), // Darwin
	}

	firefoxBinaryPaths = []string{
		"/usr/bin/firefox",                                 // Ubuntu
		`/Applications/Firefox.app/Contents/MacOS/firefox`, // Darwin
	}
)

// FirefoxStore returns a Mozilla Firefox implementation of Store
func FirefoxStore() Store {
	for i := range firefoxProfileSuggestions {
		matches, _ := filepath.Glob(firefoxProfileSuggestions[i])
		for j := range matches {
			if containsCertdb(matches[j]) {
				return NssStore("firefox", firefoxVersion(), matches[j])
			}
		}
	}
	return emptyStore{}
}

func firefoxVersion() string {
	for i := range firefoxBinaryPaths {
		path := firefoxBinaryPaths[i]
		if file.Exists(path) {
			// returns "Mozilla Firefox 57.0.3"
			out, err := exec.Command(path, "-v").CombinedOutput()
			if err == nil && len(out) > 0 {
				r := strings.NewReplacer("Mozilla Firefox", "")
				return strings.TrimSpace(r.Replace(string(out)))
			}
		}
	}
	return ""
}
