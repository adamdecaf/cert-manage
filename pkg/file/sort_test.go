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

package file

import (
	"io/ioutil"
	"sort"
	"testing"
)

func TestFile__sortStrings(t *testing.T) {
	strings := []string{"b", "A", "C", "a", " ", ""}
	sort.Sort(iStringSlice(strings))
	answer := []string{"", " ", "A", "a", "b", "C"}

	for i := range strings {
		if strings[i] != answer[i] {
			t.Fatalf("idx: %d didn't match, %s vs %s", i, strings[i], answer[i])
		}
	}
}

func TestFile__sortNames(t *testing.T) {
	names := []string{"b", "A", "C", "a", " ", ""}
	sort.Sort(iStringSlice(names))
	answer := []string{"", " ", "A", "a", "b", "C"}

	for i := range names {
		if names[i] != answer[i] {
			t.Fatalf("idx: %d didn't match, %s vs %s", i, names[i], answer[i])
		}
	}
}

func TestFile__sortFileInfos(t *testing.T) {
	fds, err := ioutil.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	answers := []string{
		"file.go",
		"file_test.go",
		"file_unix.go",
		"file_windows.go",
		"home.go",
		"home_test.go",
		"home_unix.go",
		"home_windows.go",
		"sort.go",
		"sort_test.go",
	}

	for i := range fds {
		if fds[i].Name() != answers[i] {
			t.Fatalf("idx: %d didn't match, %s vs %s", i, fds[i].Name(), answers[i])
		}
	}
}
