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
	"os"
	"testing"
)

// Check if we're online or not, via:
// - localhost icmp ping
// - TRAVIS_OS_NAME env var
func online(t *testing.T) bool {
	t.Helper()

	cmd := Command("ping", "-c1", "localhost").Trim()
	if len(cmd.output) == 0 { // no output, check for error
		defer cmd.SuccessT(t)
	}
	return inCI() || cmd.Success()
}

func inCI() bool {
	inTravis := os.Getenv("TRAVIS_OS_NAME") != ""
	inAppVeyorWin := os.Getenv("CI_WINDOWS") == "true"
	inAppVeyorLinux := os.Getenv("CI_LINUX") == "true"
	return inTravis || inAppVeyorWin || inAppVeyorLinux
}
