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

package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestGetFormatsSorted(t *testing.T) {
	got := GetFormats()
	want := append([]string(nil), got...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("GetFormats not sorted: %v", got)
	}
	joined := "," + strings.Join(got, ",") + ","
	for _, name := range []string{"json", "observatory", "openssl", "short", "table"} {
		if !strings.Contains(joined, ","+name+",") {
			t.Fatalf("GetFormats missing %s: %v", name, got)
		}
	}
}

func TestListCertificatesJSON(t *testing.T) {
	bs, err := os.ReadFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) < 1 {
		t.Fatal("no certs")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	cfg := &Config{Format: "json", SourcePath: "testdata/lots.crt"}
	err = showCertsOnCliWithPrinter(certs[:1], cfg, jsonPrinter{meta: Meta{Name: "file"}, cfg: cfg})
	_ = w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}

	var rows []jsonCert
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	row := rows[0]
	wantFP := certutil.GetHexSHA256Fingerprint(*certs[0])
	if row.SHA256 != wantFP {
		t.Fatalf("sha256=%q want %q", row.SHA256, wantFP)
	}
	if row.Subject == "" || row.Issuer == "" {
		t.Fatalf("missing subject/issuer: %+v", row)
	}
	if row.Serial != certs[0].SerialNumber.String() {
		t.Fatalf("serial=%q", row.Serial)
	}
	if row.KeyType != "RSA" || row.KeyBits != 2048 {
		t.Fatalf("key=%s/%d", row.KeyType, row.KeyBits)
	}
	if !row.IsCA {
		t.Fatal("expected is_ca")
	}
	if row.Store != "file" || row.Path != "testdata/lots.crt" {
		t.Fatalf("store/path = %q %q", row.Store, row.Path)
	}
	if row.NotBefore == "" || row.NotAfter == "" {
		t.Fatalf("missing dates: %+v", row)
	}
}

func TestTablePrinterIncludesKeyAndDays(t *testing.T) {
	bs, err := os.ReadFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tablePrinter{}.write(&buf, certs)
	out := buf.String()
	if !strings.Contains(out, "KEY") || !strings.Contains(out, "DAYS") {
		t.Fatalf("missing KEY/DAYS headers:\n%s", out)
	}
	if !strings.Contains(out, "RSA-") {
		t.Fatalf("missing KEY value:\n%s", out)
	}
}
