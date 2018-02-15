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
	urls, err := FromFile("../../../testdata/file-with-urls")
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 3 {
		t.Errorf("got %d urls", len(urls))
	}

	var ss []string
	for i := range urls {
		ss = append(ss, urls[i].String())
	}

	ans := []string{
		"https://google.com",
		"https://yahoo.com",
		"https://bing.com",
	}
	if !reflect.DeepEqual(ss, ans) {
		t.Errorf("got %q", ss)
	}
}
