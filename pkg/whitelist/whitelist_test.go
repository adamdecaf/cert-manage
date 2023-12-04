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

package whitelist

import (
	"os"
	"reflect"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
)

func TestWhitelist_nocert(t *testing.T) {
	cases := []Whitelist{
		{},
		{
			Fingerprints: []string{"a"},
		},
		{
			Countries: []string{"US"},
		},
	}
	for i := range cases {
		wh := cases[i]
		if wh.Matches(nil) {
			t.Errorf("shouldn't have matched, wh=%#v", wh)
		}
	}
}

func TestWhitelist_emptywhitelist(t *testing.T) {
	wh := Whitelist{}
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	for i := range certs {
		if wh.Matches(certs[i]) {
			t.Fatalf("err, empty whitelist shouldn't match")
		}
	}
}

func TestWhitelist_remove(t *testing.T) {
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}

	// test fingerprint
	wh := Whitelist{
		Fingerprints: []string{
			"05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030",
		},
	}
	for i := range certs {
		if !wh.Matches(certs[i]) {
			t.Fatalf("should have matched")
		}
	}

	// test country
	wh = Whitelist{
		Countries: []string{"US"},
	}
	for i := range certs {
		if !wh.Matches(certs[i]) {
			t.Fatalf("should have matched")
		}
	}
}

func TestWhitelist__jsonFile(t *testing.T) {
	wh, err := FromFile("../../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.Fingerprints) != 1 {
		t.Errorf("Wrong number of parsed fingerprints in whitelist, found=%d", len(wh.Fingerprints))
	}

	if !reflect.DeepEqual(wh.Fingerprints, []string{"a"}) {
		t.Errorf("got %q", wh.Fingerprints)
	}

	if !reflect.DeepEqual(wh.Countries, []string{"US", "GB"}) {
		t.Errorf("got %q", wh.Countries)
	}
}

func TestWhitelist__emptyJson(t *testing.T) {
	wh, err := FromFile("../../testdata/empty-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.Fingerprints) != 0 {
		t.Errorf("empty whitelist had fingerprints: %q", wh.Fingerprints)
	}
	if len(wh.Countries) != 0 {
		t.Errorf("empty whitelist had countries: %q", wh.Countries)
	}
}

func TestWhitelist__yamlFile(t *testing.T) {
	wh, err := FromFile("../../testdata/complete-whitelist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.Fingerprints) != 1 {
		t.Errorf("Wrong number of parsed fingerprints in whitelist, found=%d", len(wh.Fingerprints))
	}

	if !reflect.DeepEqual(wh.Fingerprints, []string{"a"}) {
		t.Errorf("got %q", wh.Fingerprints)
	}

	if !reflect.DeepEqual(wh.Countries, []string{"US", "GB"}) {
		t.Errorf("got %q", wh.Countries)
	}
}

func TestWhitelist__emptyYaml(t *testing.T) {
	wh, err := FromFile("../../testdata/empty-whitelist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.Fingerprints) != 0 {
		t.Errorf("empty whitelist had fingerprints: %q", wh.Fingerprints)
	}
	if len(wh.Countries) != 0 {
		t.Errorf("empty whitelist had countries: %q", wh.Countries)
	}
}

func TestWhitelist_cycle(t *testing.T) {
	wh, err := FromFile("../../testdata/complete-whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	where := "../../test-whitelist.json"
	defer os.Remove(where)
	if err = wh.ToFile(where); err != nil {
		t.Fatal(err)
	}
	wh2, err := FromFile(where)
	if err != nil {
		t.Fatal(err)
	}
	if len(wh.Fingerprints) != len(wh2.Fingerprints) {
		t.Errorf("%d != %d", len(wh.Fingerprints), len(wh2.Fingerprints))
	}
}

func TestWhitlist__matching(t *testing.T) {
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

	wh := Whitelist{}
	if wh.Matches(certificates[0]) {
		t.Error("empty whitelist and cert shouldn't match")
	}

	// Fingerprints
	wh.Fingerprints = []string{"abc"}
	if wh.Matches(certificates[0]) {
		t.Error("shouldn't match")
	}

	wh.Fingerprints = []string{"05a6db38939"}
	if wh.Matches(certificates[0]) {
		t.Errorf("%q shouldn't mattch, (short fingerprints not allowed)", wh.Fingerprints)
	}

	wh.Fingerprints = []string{"05a6db389391df92e0be93fdfa4db1e3cf53903918b8d9d85a9c396cb55df030"}
	if !wh.Matches(certificates[0]) {
		t.Error("should have matched")
	}

	// Country
	wh.Fingerprints = []string{}
	wh.Countries = []string{"US"}
	if !wh.Matches(certificates[0]) {
		t.Error("should have matched")
	}
}
