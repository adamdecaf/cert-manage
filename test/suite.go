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
	"strconv"
	"testing"
)

type cfg struct {
	total, after string
	curlExitCode string
}

func (c *cfg) failIfEmpty(t *testing.T) {
	t.Helper()

	if c.total == "" || c.after == "" {
		t.Fatalf("total=%q or after=%q is blank", c.total, c.after)
	}
	if c.curlExitCode == "" {
		t.Fatal("missing curlExitCode")
	}
}

func linuxSuite(t *testing.T, img *dockerfile, config cfg) {
	config.failIfEmpty(t)

	if debug {
		fmt.Println("Linux start")
	}

	// List
	img.CertManage("list", "-count", "|", "grep", config.total)
	// Backup
	img.CertManage("backup")
	img.RunSplit(fmt.Sprintf("ls -1 /usr/share/ca-certificates/* | wc -l | grep %s", config.total))
	img.RunSplit("ls -1 ~/.cert-manage/linux | wc -l | grep 1")
	// Whitelist
	img.CertManage("whitelist", "-file", "/whitelist.json")
	img.CertManage("list", "-count", "|", "grep", config.after)
	// Verify our test domain fails to load
	img.ExitCode(config.curlExitCode, "curl", "-I", "https://www.yahoo.com/")
	// Restore
	img.CertManage("restore")
	// Verify Restore
	img.CertManage("list", "-count", "|", "grep", config.total)
	img.Run("curl", "-I", "https://www.yahoo.com/")
	// Add certificate
	img.CertManage("add", "-file", "/localcert.pem")
	img.CertManage("list", "-count", "|", "grep", incr(config.total))
	img.SuccessT(t)

	if debug {
		fmt.Println("Linux end")
	}
}

func javaSuite(t *testing.T, img *dockerfile, total, after string) {
	if total == "" || after == "" {
		t.Fatalf("total=%q or after=%q is blank", total, after)
	}
	if debug {
		fmt.Println("Java start")
	}

	// List
	img.CertManageEQ("list -count -app java", total)
	// Backup
	img.CertManage("backup", "-app", "java")
	img.RunSplit("ls -1 ~/.cert-manage/java | wc -l | grep 1")
	// Check java
	img.RunSplit("cd / && java Download")
	// Whitelist java
	img.CertManage("whitelist", "-app", "java", "-file", "/whitelist.yaml")
	img.CertManageEQ("list -app java -count", after)
	// Verify google.com fails to load
	img.Run("cd", "/")
	img.ShouldFail("java", "Download", "2>&1", "|", "grep", `'PKIX path building failed'`)
	// Restore
	img.CertManage("restore", "-app", "java")
	img.CertManageEQ("list -app java -count", total)
	// Verify Restore
	img.RunSplit("cd / && java Download")
	// Add certificate
	img.CertManage("add", "-file", "/localcert.pem", "-app", "java")
	img.CertManageEQ("list -count -app java", incr(total))
	img.SuccessT(t)

	if debug {
		fmt.Println("Java end")
	}
}

func incr(in string) string {
	n, err := strconv.Atoi(in)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%d", n+1)
}
