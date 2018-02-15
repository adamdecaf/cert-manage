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

// +build darwin

package test

import (
	// "strings"
	"testing"
)

func TestIntegration__date(t *testing.T) {
	cmd := Command("date", "-u", "-r", "0").Trim()
	cmd.EqualT(t, "Thu Jan  1 00:00:00 UTC 1970")

	ans := `Command:
  date -u -r 0
Output:
  Thu Jan  1 00:00:00 UTC 1970`
	if cmd.String() != ans {
		t.Errorf("cmd.String() = %q", cmd.String())
	}
}

func TestIntegration__unknown(t *testing.T) {
	cmd := CertManage("other").Trim()
	cmd.FailedT(t)
}

func TestIntegration__list(t *testing.T) {
	t.Skip("darwin support is wip")

	cmd := CertManage("list", "-count").Trim()
	cmd.CmpIntF(t, func(i int) bool { return i > 1 })
}

func TestIntegration__listFromFile(t *testing.T) {
	cmd := CertManage("list", "-file", "../testdata/lots.crt", "-count").Trim()
	cmd.CmpIntF(t, func(i int) bool { return i == 5 })
}

func TestIntegration__backup(t *testing.T) {
	cmd := CertManage("backup").Trim()
	cmd.EqualT(t, "Backup completed successfully")
}

// TODO(adam): Need to run -whitelist and -restore

// Firefox tests
// func TestIntegration__firefox(t *testing.T) {
// 	if !online(t) {
// 		t.Skip("offline, can't run firefox tests (no NSS setup)")
// 	}

// 	// Make a request using the Keychain to get it ready
// 	// travis needs this
// 	cmd := Command("timeout", strings.Split("15s firefox --headless https://google.com 2>&1 >> /var/log/firefox.log", " ")...)
// 	cmd.SuccessT(t)

// 	// Verify firefox has found certificates
// 	cmd = CertManage("list", "-app", "firefox", "-count").Trim()
// 	cmd.SuccessT(t)
// 	cmd.CmpIntF(t, func(i int) bool { return i > 1 })
// }
