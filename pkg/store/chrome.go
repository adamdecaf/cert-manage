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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

var (
	chromeBinaryPaths = []string{
		"/usr/bin/chromium-browser",                                    // Chromium
		`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, // OSX
	}
)

// ChromeStore returns a Google Chrome implementation of Store
// Docs:
//   - https://www.chromium.org/Home/chromium-security/root-ca-policy
//   - https://chromium.googlesource.com/chromium/src/+/master/docs/linux_cert_management.md
func ChromeStore() Store {
	switch runtime.GOOS {
	case "darwin", "windows":
		// we need to wrap the platform store and override GetInfo() for
		// chrome's name/version
		return chromeStore{
			Platform(),
		}
	case "linux":
		where := filepath.Join(file.HomeDir(), ".pki/nssdb")
		if _, err := os.Stat(where); !os.IsNotExist(err) {
			return NssStore("chrome", chromeVersion(), where)
		}
	}
	return emptyStore{}
}

type chromeStore struct {
	Store
}

func (s chromeStore) GetInfo() *Info {
	return &Info{
		Name:    "Chrome",
		Version: chromeVersion(),
	}
}

func chromeVersion() string {
	for i := range chromeBinaryPaths {
		path := chromeBinaryPaths[i]
		if file.Exists(path) {
			// returns "Google Chrome 63.0.3239.132"
			out, err := exec.Command(path, "--version").CombinedOutput()
			if err == nil && len(out) > 0 {
				ver := string(out)

				// Drop prefix
				r := strings.NewReplacer("Google Chrome", "")
				ver = strings.TrimSpace(r.Replace(ver))
				r = strings.NewReplacer("Chromium", "")
				ver = strings.TrimSpace(r.Replace(ver))

				// Drop optional suffix
				parts := strings.Fields(ver)
				if len(parts) > 0 {
					// Return just the version
					// Original: 'Chromium 64.0.3282.140 Built on Ubuntu , running on Ubuntu 17.10'
					// Note: 'Chromium' is dropped first
					return parts[0]
				}
				return ver
			}
		}
	}
	return ""
}
