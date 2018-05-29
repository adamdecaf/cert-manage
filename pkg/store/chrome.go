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
	"runtime" 
	"strings" 
 
	"github.com/adamdecaf/cert-manage/pkg/file" 
) 
 
var ( 
	chromeBinaryPaths = []string{ 
		// TODO(adam): Support other OS's (and probably Chromium) 
		`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, 
	} 
) 
 
// ChromeStore returns a Google Chrome implementation of Store 
// Docs: https://www.chromium.org/Home/chromium-security/root-ca-policy 
func ChromeStore() Store { 
	switch runtime.GOOS { 
	case "darwin", "windows": 
		// we need to wrap the platform store and override GetInfo() for 
		// chrome's name/version 
		return chromeStore{ 
			Platform(), 
		} 
	case "linux": 
		return chromeLinux() 
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
				r := strings.NewReplacer("Google Chrome", "") 
				return strings.TrimSpace(r.Replace(string(out))) 
			} 
		} 
	} 
	return "" 
} 
 
func chromeCertdbLocations() []cert8db { 
	uhome := file.HomeDir() 
	if uhome == "" { 
		if debug { 
			fmt.Println("store/chrome: unable to find user's home dir") 
		} 
		return nil 
	} 
 
	return []cert8db{ 
		cert8db(filepath.Join(uhome, ".pki/nssdb")), 
	} 
} 
 
func chromeLinux() Store { 
	suggestions := chromeCertdbLocations() 
	found := locateCert8db(suggestions) 
	return NssStore("chrome", chromeVersion(), suggestions, found) 
} 
