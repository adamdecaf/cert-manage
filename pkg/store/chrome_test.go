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
	"strings"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

func TestStoreChrome__info(t *testing.T) {
	ver := chromeVersion()

	// OSX
	if file.Exists(`/Applications/Google Chrome.app`) {
		if ver == "" {
			t.Error("blank Version")
		}
		if strings.Contains(ver, " ") {
			t.Errorf("has spaces, version=%q", ver)
		}
	}

	// Linux
	if file.Exists("/usr/bin/chromium-browser") {
		if ver == "" {
			t.Error("blank Version")
		}
		if strings.Contains(ver, " ") {
			t.Errorf("has spaces, version=%q", ver)
		}
	}
}
