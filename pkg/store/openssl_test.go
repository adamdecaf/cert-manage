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
	"testing"
)

func TestStoreOpenSSL__paths(t *testing.T) {
	err := exec.Command("openssl", "version").Run()
	if err != nil {
		t.Skipf("can't find openssl, err=%v", err)
	}

	st := opensslStore{}
	dir, err := st.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if dir == "" {
		t.Error("empty dir")
	}
}
