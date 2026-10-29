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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/store"
)

func TestPrintAppsTerse(t *testing.T) {
	t.Parallel()

	statuses := []store.Status{
		{Name: "chrome", Found: true, Path: "/tmp/chrome-nss"},
		{Name: "firefox", Found: false, Path: ""},
		{Name: "platform", Found: true, Path: "/etc/ssl/certs/ca-certificates.crt"},
	}
	var buf bytes.Buffer
	if err := printApps(&buf, statuses, ""); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], "chrome") || !strings.Contains(lines[0], "found") || !strings.Contains(lines[0], "/tmp/chrome-nss") {
		t.Errorf("chrome line = %q", lines[0])
	}
	if !strings.Contains(lines[1], "firefox") || !strings.Contains(lines[1], "not-found") || !strings.HasSuffix(strings.TrimSpace(lines[1]), "-") {
		t.Errorf("firefox line = %q", lines[1])
	}
	// Names should be padded to the longest ("platform")
	if !strings.HasPrefix(lines[0], "chrome  ") {
		t.Errorf("expected chrome padded to platform width, got %q", lines[0])
	}
}

func TestPrintAppsJSON(t *testing.T) {
	t.Parallel()

	statuses := []store.Status{
		{Name: "java", Found: false, Path: ""},
		{Name: "openssl", Found: true, Path: "/etc/ssl/certs/ca-certificates.crt"},
	}
	var buf bytes.Buffer
	if err := printApps(&buf, statuses, "json"); err != nil {
		t.Fatal(err)
	}
	var got []store.Status
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\nraw: %s", err, buf.String())
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %#v", got)
	}
	if got[0].Name != "java" || got[0].Found {
		t.Errorf("java entry = %#v", got[0])
	}
	if got[1].Name != "openssl" || !got[1].Found || got[1].Path == "" {
		t.Errorf("openssl entry = %#v", got[1])
	}
}

func TestPrintAppsUnknownFormat(t *testing.T) {
	t.Parallel()

	err := printApps(&bytes.Buffer{}, nil, "openssl")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "json") {
		t.Errorf("error should say what to do next, got %v", err)
	}
}
