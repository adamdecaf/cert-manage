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

package allowlist

import (
	"os"
	"reflect"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestAllowlist_nocert(t *testing.T) {
	cases := []Allowlist{
		{},
		{
			Fingerprints: []string{"a"},
		},
		{
			Countries: []string{"US"},
		},
	}
	for i := range cases {
		al := cases[i]
		if al.Matches(nil) {
			t.Errorf("shouldn't have matched, al=%#v", al)
		}
	}
}

func TestAllowlist_emptyallowlist(t *testing.T) {
	al := Allowlist{}
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	for i := range certs {
		if al.Matches(certs[i]) {
			t.Fatalf("err, empty allowlist shouldn't match")
		}
	}
}

func TestAllowlist_remove(t *testing.T) {
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	// test fingerprint
	al := Allowlist{
		Fingerprints: []string{
			"05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030",
		},
	}
	for i := range certs {
		if !al.Matches(certs[i]) {
			t.Fatalf("should have matched")
		}
	}

	// test country
	al = Allowlist{
		Countries: []string{"US"},
	}
	for i := range certs {
		if !al.Matches(certs[i]) {
			t.Fatalf("should have matched")
		}
	}
}

func TestAllowlist__jsonFile(t *testing.T) {
	al, err := FromFile("../../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 1 {
		t.Errorf("Wrong number of parsed fingerprints in allowlist, found=%d", len(al.Fingerprints))
	}

	if !reflect.DeepEqual(al.Fingerprints, []string{"a"}) {
		t.Errorf("got %q", al.Fingerprints)
	}

	if !reflect.DeepEqual(al.Countries, []string{"US", "GB"}) {
		t.Errorf("got %q", al.Countries)
	}
}

func TestAllowlist__emptyJson(t *testing.T) {
	al, err := FromFile("../../testdata/empty-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 0 {
		t.Errorf("empty allowlist had fingerprints: %q", al.Fingerprints)
	}
	if len(al.Countries) != 0 {
		t.Errorf("empty allowlist had countries: %q", al.Countries)
	}
}

func TestAllowlist__yamlFile(t *testing.T) {
	al, err := FromFile("../../testdata/complete-whitelist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 1 {
		t.Errorf("Wrong number of parsed fingerprints in allowlist, found=%d", len(al.Fingerprints))
	}

	if !reflect.DeepEqual(al.Fingerprints, []string{"a"}) {
		t.Errorf("got %q", al.Fingerprints)
	}

	if !reflect.DeepEqual(al.Countries, []string{"US", "GB"}) {
		t.Errorf("got %q", al.Countries)
	}
}

func TestAllowlist__emptyYaml(t *testing.T) {
	al, err := FromFile("../../testdata/empty-whitelist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 0 {
		t.Errorf("empty allowlist had fingerprints: %q", al.Fingerprints)
	}
	if len(al.Countries) != 0 {
		t.Errorf("empty allowlist had countries: %q", al.Countries)
	}
}

func TestAllowlist__globalsignJson(t *testing.T) {
	al, err := FromFile("../../testdata/globalsign-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != 6 {
		t.Errorf("Wrong number of parsed fingerprints in allowlist, found=%d", len(al.Fingerprints))
	}
	if len(al.Countries) != 0 {
		t.Errorf("got countries %q", al.Countries)
	}
}

func TestAllowlist__usYaml(t *testing.T) {
	al, err := FromFile("../../testdata/us-whitelist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(al.Countries, []string{"US"}) {
		t.Errorf("got %q", al.Countries)
	}
	if len(al.Fingerprints) != 0 {
		t.Errorf("got fingerprints %q", al.Fingerprints)
	}
}

func TestAllowlist__testJson(t *testing.T) {
	al, err := FromFile("../../testdata/test-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) < 1 {
		t.Errorf("expected fingerprints in testdata/test-whitelist.json, got %q", al.Fingerprints)
	}
}

func TestAllowlist_cycle(t *testing.T) {
	al, err := FromFile("../../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	where := "../../test-allowlist.json"
	defer os.Remove(where)
	if err = al.ToFile(where); err != nil {
		t.Fatal(err)
	}
	al2, err := FromFile(where)
	if err != nil {
		t.Fatal(err)
	}
	if len(al.Fingerprints) != len(al2.Fingerprints) {
		t.Errorf("%d != %d", len(al.Fingerprints), len(al2.Fingerprints))
	}
}

func TestAllowlist__matching(t *testing.T) {
	certificates, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 1 {
		t.Errorf("got %d certs", len(certificates))
	}
	if certificates[0] == nil {
		t.Error("Unable to read first cert")
	}

	al := Allowlist{}
	if al.Matches(certificates[0]) {
		t.Error("empty allowlist and cert shouldn't match")
	}

	// Fingerprints
	al.Fingerprints = []string{"abc"}
	if al.Matches(certificates[0]) {
		t.Error("shouldn't match")
	}

	al.Fingerprints = []string{"05a6db38939"}
	if al.Matches(certificates[0]) {
		t.Errorf("%q shouldn't mattch, (short fingerprints not allowed)", al.Fingerprints)
	}

	al.Fingerprints = []string{"05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030"}
	if !al.Matches(certificates[0]) {
		t.Error("should have matched")
	}

	// Country
	al.Fingerprints = []string{}
	al.Countries = []string{"US"}
	if !al.Matches(certificates[0]) {
		t.Error("should have matched")
	}
}

func TestAllowlist_blocklistedFingerprintsLoad(t *testing.T) {
	if len(blocklistedFingerprints) == 0 {
		t.Fatal("blocklistedFingerprints is empty")
	}
	// Qaznet Trust Network fingerprint from Chromium's current blocklist.
	const refreshed = "00309c736dd661da6f1eb24173aa849944c168a43a15bffd192eecfdb6f8dbd2"
	for i := range blocklistedFingerprints {
		if blocklistedFingerprints[i] == refreshed {
			return
		}
	}
	t.Fatalf("refreshed Chromium fingerprint %q is missing", refreshed)
}

func TestAllowlist_blocklistRejectsMatch(t *testing.T) {
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 || certs[0] == nil {
		t.Fatal("expected example.crt")
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	orig := blocklistedFingerprints
	t.Cleanup(func() { blocklistedFingerprints = orig })
	blocklistedFingerprints = append([]string{fp}, blocklistedFingerprints...)

	al := Allowlist{Fingerprints: []string{fp}}
	if al.Matches(certs[0]) {
		t.Fatal("blocklisted fingerprint should not match even if it is on the allowlist")
	}
}
