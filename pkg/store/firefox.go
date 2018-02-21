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
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

// returns a slice of "suggestions" for where cert8.db files live.
// The idea of tihs slice is to generalize over randomly named directories
// (how firefox names profiles) and handle user-specific filepaths
func firefoxCertdbLocations() []cert8db {
	uhome := file.HomeDir()
	if uhome == "" {
		if debug {
			fmt.Println("store/firefox: unable to find user's home dir")
		}
		return nil
	}

	paths := []cert8db{
		cert8db(filepath.Join(uhome, ".mozilla/firefox/*.default")),                              // Linux
		cert8db(filepath.Join(uhome, "/Library/Application Support/Firefox/Profiles/*.default")), // darwin
	}

	return paths
}

// FirefoxStore returns a Mozilla Firefox implementation of Store
func FirefoxStore() Store {
	suggestions := firefoxCertdbLocations()
	found := locateCert8db(suggestions)
	return NssStore("firefox", firefoxVersion(), suggestions, found)
}

var (
	firefoxBinaryPaths = []string{
		// TODO(adam): Support other OS's
		`/Applications/Firefox.app/Contents/MacOS/firefox`,
	}
)

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
