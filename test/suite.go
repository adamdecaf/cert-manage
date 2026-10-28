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
	"fmt"
	"testing"
)

func linuxSuite(t *testing.T, img *dockerfile) {
	if debug {
		fmt.Println("Linux start")
	}

	img.Run("sh", "-c", `total=$(/bin/cert-manage list -count); echo "$total" > /tmp/total; echo "linux certs=$total"; test "$total" -gt 10`)
	img.CertManage("backup")
	img.Run("sh", "-c", `test "$(ls -1 ~/.cert-manage/linux | wc -l | tr -d ' ')" -ge 1`)
	img.CertManage("whitelist", "-file", "/whitelist.json")
	img.Run("sh", "-c", `after=$(/bin/cert-manage list -count); test "$after" -lt "$(cat /tmp/total)"`)
	img.Run("set +e")
	img.Run("curl", "-fsS", "-o", "/dev/null", "-I", "--max-time", "20", "https://www.yahoo.com/")
	img.Run("code=$?")
	img.Run("set -e")
	img.Run("test", "$code", "-ne", "0")
	img.CertManage("restore")
	img.Run("sh", "-c", `test "$(/bin/cert-manage list -count)" -eq "$(cat /tmp/total)"`)
	img.Run("curl", "-fsS", "-o", "/dev/null", "-I", "--max-time", "20", "https://www.yahoo.com/")
	img.CertManage("add", "-file", "/localcert.pem")
	img.Run("sh", "-c", `test "$(/bin/cert-manage list -count)" -eq $(( $(cat /tmp/total) + 1 ))`)
	img.SuccessT(t)

	if debug {
		fmt.Println("Linux end")
	}
}

func javaSuite(t *testing.T, img *dockerfile) {
	if debug {
		fmt.Println("Java start")
	}

	img.Run("sh", "-c", `total=$(/bin/cert-manage list -count -app java); echo "$total" > /tmp/jtotal; echo "java certs=$total"; test "$total" -gt 10`)
	img.CertManage("backup", "-app", "java")
	img.Run("sh", "-c", `test "$(ls -1 ~/.cert-manage/java | wc -l | tr -d ' ')" -ge 1`)
	img.RunSplit("cd / && java Download")
	img.CertManage("whitelist", "-app", "java", "-file", "/whitelist.yaml")
	img.Run("sh", "-c", `after=$(/bin/cert-manage list -count -app java); test "$after" -lt "$(cat /tmp/jtotal)"`)
	img.CertManage("restore", "-app", "java")
	img.Run("sh", "-c", `test "$(/bin/cert-manage list -count -app java)" -eq "$(cat /tmp/jtotal)"`)
	img.RunSplit("cd / && java Download")
	img.CertManage("add", "-file", "/localcert.pem", "-app", "java")
	img.Run("sh", "-c", `test "$(/bin/cert-manage list -count -app java)" -eq $(( $(cat /tmp/jtotal) + 1 ))`)
	img.SuccessT(t)

	if debug {
		fmt.Println("Java end")
	}
}

func firefoxSuite(t *testing.T, img *dockerfile, total, after string) {
	if total == "" || after == "" {
		t.Fatalf("total=%q or after=%q is blank", total, after)
	}
	if debug {
		fmt.Println("Firefox start")
	}

	img.RunSplit("ls -al ~/")
	img.SuccessT(t)

	if debug {
		fmt.Println("Firefox end")
	}
}
