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
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

// FromFile reads a text file and grabs urls separated by newlines
func FromFile(path string) ([]*url.URL, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if !file.Exists(path) {
		return nil, fmt.Errorf("%q doesn't exist", path)
	}

	// read file, scan lines and pull out each line which parses
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var res []*url.URL
	rdr := bufio.NewScanner(fd)
	for rdr.Scan() {
		line := strings.TrimSpace(rdr.Text())
		if line != "" {
			u, err := url.Parse(line)
			if err == nil && u != nil {
				res = append(res, u)
			}
		}
	}
	return res, nil
}
