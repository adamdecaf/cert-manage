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

package main

import (
	"flag"
	"strings"
	"testing"
)

func TestParseConnectUrl(t *testing.T) {
	reset := func() {
		*flagURL = ""
	}
	t.Cleanup(reset)

	t.Run("positional", func(t *testing.T) {
		reset()
		fs := flag.NewFlagSet("connect", flag.ContinueOnError)
		if err := fs.Parse([]string{"https://example.com"}); err != nil {
			t.Fatal(err)
		}
		u, err := parseConnectUrl(fs)
		if err != nil {
			t.Fatal(err)
		}
		if u.String() != "https://example.com" {
			t.Fatalf("got %s", u)
		}
	})

	t.Run("flagURL", func(t *testing.T) {
		reset()
		*flagURL = "https://example.com/via-flag"
		fs := flag.NewFlagSet("connect", flag.ContinueOnError)
		if err := fs.Parse([]string{}); err != nil {
			t.Fatal(err)
		}
		u, err := parseConnectUrl(fs)
		if err != nil {
			t.Fatal(err)
		}
		if u.String() != "https://example.com/via-flag" {
			t.Fatalf("got %s", u)
		}
	})

	t.Run("both rejected", func(t *testing.T) {
		reset()
		*flagURL = "https://example.com/flag"
		fs := flag.NewFlagSet("connect", flag.ContinueOnError)
		if err := fs.Parse([]string{"https://example.com/pos"}); err != nil {
			t.Fatal(err)
		}
		_, err := parseConnectUrl(fs)
		if err == nil || !strings.Contains(err.Error(), "not both") {
			t.Fatalf("expected both-rejected error, got %v", err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		reset()
		fs := flag.NewFlagSet("connect", flag.ContinueOnError)
		if err := fs.Parse([]string{}); err != nil {
			t.Fatal(err)
		}
		_, err := parseConnectUrl(fs)
		if err == nil || !strings.Contains(err.Error(), "no url") {
			t.Fatalf("expected missing url error, got %v", err)
		}
	})
}
