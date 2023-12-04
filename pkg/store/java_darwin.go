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

//go:build darwin
// +build darwin

package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

var ktool keytool

func init() {
	full := expandKnownJavaInstall()
	if full == "" {
		full = "/Library/Java/JavaVirtualMachines/"
	}

	ktool = keytool{
		javahome:         os.Getenv("JAVA_HOME"),
		javaInstallPaths: []string{full},
		relativeKeystorePaths: []string{
			"/lib/security/cacerts",
			"/jre/lib/security/cacerts", // OSX 10.10.1
		},
	}
}

func expandKnownJavaInstall() string {
	full := "/System/Library/Frameworks/JavaVM.framework/Versions/Current/Commands/java_home"
	if file.Exists(full) && file.IsExecutable(full) {
		// We need to exec the script and return its result as JAVA_HOME
		out, err := exec.Command(full).Output()
		if err != nil {
			// return we found nothing
			return ""
		}
		return filepath.Clean(strings.TrimSpace(string(out)))
	}
	return ""
}
