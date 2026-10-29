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

package gen

import (
	"reflect"
	"testing"
)

func TestGen_fromFile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path   string
		count  int
		answer []string
	}{
		{
			path:  "../../../testdata/file-with-urls",
			count: 3,
			answer: []string{
				"https://google.com",
				"https://yahoo.com",
				"https://bing.com",
			},
		},
		{
			path:  "../../../testdata/tranco-sample.csv",
			count: 4,
			answer: []string{
				"https://google.com",
				"https://youtube.com",
				"https://facebook.com",
				"https://example.com",
			},
		},
		{
			path:  "../../../testdata/tranco-sample.csv.gz",
			count: 4,
			answer: []string{
				"https://google.com",
				"https://youtube.com",
				"https://facebook.com",
				"https://example.com",
			},
		},
		{
			path:  "../../../testdata/alexa-top-1m.csv.gz",
			count: 1e6,
			answer: []string{
				"https://google.com", // first row only checked below when answer length < count
			},
		},
		{
			path:  "../../../testdata/cisco-top-1m.csv.gz",
			count: 1e6,
		},
	}

	for i := range cases {
		urls, err := FromFile(cases[i].path)
		if err != nil {
			t.Fatal(err)
		}
		if len(urls) != cases[i].count {
			t.Errorf("%s got %d urls", cases[i].path, len(urls))
		}
		if cases[i].answer == nil {
			continue
		}
		if len(cases[i].answer) < cases[i].count {
			// Spot-check the first URL on large lists.
			if urls[0].String() != cases[i].answer[0] {
				t.Errorf("%s first url=%q want %q", cases[i].path, urls[0], cases[i].answer[0])
			}
			continue
		}
		var ss []string
		for j := range urls {
			ss = append(ss, urls[j].String())
		}
		if !reflect.DeepEqual(ss, cases[i].answer) {
			t.Errorf("%s got %q", cases[i].path, ss)
		}
	}
}

func TestFindURLInLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want string
	}{
		{"https://google.com", "https://google.com"},
		{"1,google.com", "https://google.com"},
		{" 42 , example.com ", "https://example.com"},
		{"# comment", ""},
		{"", ""},
		{"not a url", ""},
		{"google.com", ""}, // bare domain without rank is ignored
		{"1,https://evil.example", ""}, // scheme in domain column rejected
	}
	for _, tc := range cases {
		u := findURLInLine(tc.line)
		got := ""
		if u != nil {
			got = u.String()
		}
		if got != tc.want {
			t.Errorf("findURLInLine(%q)=%q want %q", tc.line, got, tc.want)
		}
	}
}
