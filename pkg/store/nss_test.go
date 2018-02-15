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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreNSS_certdbDiscovery(t *testing.T) {
	// create a dir, add a 'cert8.db' file and verify we can discover it
	tmp, err := ioutil.TempDir("", "nss-discovery")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmp)

	// Very we don't find anything in an empty dir
	in := make([]cert8db, 1)
	in[0] = cert8db(tmp)
	if found := locateCert8db(in); !found.empty() {
		t.Errorf("shouldn't have found cert8.db files in %s", tmp)
	}
	if containsCert8db(tmp) {
		t.Errorf("%s shouldn't contain a cert8.db", tmp)
	}

	// Create a blank cert8.db file
	where := filepath.Join(tmp, "cert8.db")
	err = ioutil.WriteFile(where, []byte("data"), 0644)
	if err != nil {
		t.Error(err)
	}

	// Now we should find the cert8.db path
	if !containsCert8db(tmp) {
		t.Errorf("should have found cert8.db in %s", tmp)
	}
}

func TestStoreNSS_trustedForSSL(t *testing.T) {
	trusted := map[string]bool{
		// trusted attrs
		"c,c,c": true,
		",,":    true,
		"CT,,":  true,
		"u,,":   true,
		"wC,,":  true,
		// not trusted
		"p,p,p": false,
		"p,,":   false,
	}
	for attrs, answer := range trusted {
		item := cert8Item{trustAttrs: attrs}
		if res := item.trustedForSSL(); res != answer {
			t.Errorf("attrs (%s), trustedForSSL()=%v should be %v", attrs, res, answer)
		}
	}
}
