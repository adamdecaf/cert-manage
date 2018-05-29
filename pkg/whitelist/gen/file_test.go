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
			path:  "../../../testdata/alexa-top-1m.csv.gz", 
			count: 1e6, 
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
		if cases[i].answer != nil { 
			var ss []string 
			for i := range urls { 
				ss = append(ss, urls[i].String()) 
			} 
			if !reflect.DeepEqual(ss, cases[i].answer) { 
				t.Errorf("%s got %q", cases[i].path, ss) 
			} 
		} 
	} 
} 
