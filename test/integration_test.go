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

package test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/cmd"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

// high-level test of entire "gen-whitelist" code path
func TestIntegraton__genWhitelist(t *testing.T) {
	t.Parallel()

	dir, err := ioutil.TempDir("", "gen-whitelist")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "whitelist.json")

	// generate whitelist
	err = cmd.GenerateWhitelist(output, "", "../testdata/file-with-urls")
	if err != nil {
		t.Fatal(err)
	}

	// read whitelist, loosely verify
	wh, err := whitelist.FromFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.Fingerprints) != 3 {
		t.Errorf("got %q", wh.Fingerprints)
	}
}
