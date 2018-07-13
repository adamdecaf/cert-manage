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

package cmd

import (
	"fmt"
	"net/url"
	"os"
	"testing"
)

var (
	connectExampleApp = "java"
	connectExampleUrl *url.URL
)

func init() {
	raw := "https://example.com"
	u, err := url.Parse(raw)
	if err != nil {
		panic(fmt.Sprintf("problem parsing %s: %v", raw, err))
	}
	connectExampleUrl = u
}

func TestCmdConnect_platform(t *testing.T) {
	t.Parallel()

	if err := ConnectWithPlatformStore(connectExampleUrl); err != nil {
		t.Fatalf("problem with -connect on platform store: %v", err)
	}
}

func TestCmdConnect_app(t *testing.T) {
	t.Parallel()

	if os.Getenv("JAVA_HOME") == "" {
		t.Skip("can't quickly find java")
	}

	if err := ConnectWithAppStore(connectExampleUrl, connectExampleApp); err != nil {
		t.Fatalf("problem with -connect on %s store: %v", connectExampleApp, err)
	}
}
