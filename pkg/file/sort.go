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
	"os"
	"sort"
	"strings"
)

// iStringSlice is a case-insensitive string sorting implementation
type iStringSlice []string

func (p iStringSlice) Len() int {
	return len(p)
}

func (p iStringSlice) Less(i, j int) bool {
	return strings.ToLower(p[i]) < strings.ToLower(p[j])
}

func (p iStringSlice) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func SortNames(ss []string) {
	sort.Sort(iStringSlice(ss))
}

// iFileInfo is a case-insensitive os.FileInfo sorting (by .Name())
// implementation
type iFileInfo []os.FileInfo

func (p iFileInfo) Len() int {
	return len(p)
}

func (p iFileInfo) Less(i, j int) bool {
	return strings.ToLower(p[i].Name()) < strings.ToLower(p[j].Name())
}

func (p iFileInfo) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func SortFileInfos(fis []os.FileInfo) {
	sort.Sort(iFileInfo(fis))
}
