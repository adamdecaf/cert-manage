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
	"bytes" 
	"compress/gzip" 
	"fmt" 
	"io" 
	"net/url" 
	"os" 
	"path/filepath" 
	"strings" 
 
	"github.com/adamdecaf/cert-manage/pkg/file" 
) 
 
var ( 
	gzipHeader = []byte{0x1f, 0x8b} 
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
	rdr := bufio.NewScanner(decodeIfGzipped(fd)) 
 
	for rdr.Scan() { 
		if u := findUrlInLine(rdr.Text()); u != nil { 
			res = append(res, u) 
		} 
	} 
	return res, nil 
} 
 
// decodeIfGzipped attempts to wrap the bufio.Reader if the header contains the gzip 
// magic header, otherwise the original reader is returned. 
func decodeIfGzipped(r io.Reader) io.Reader { 
	rdr := bufio.NewReader(r) 
	bs, err := rdr.Peek(2) 
	if err != nil { 
		// Probably not a good thing we error'd, probably io.EOF or something 
		return r 
	} 
	if bytes.Equal(bs, gzipHeader) { 
		rdr, err := gzip.NewReader(rdr) 
		if err != nil { 
			return r // don't wrap reader in gzip 
		} 
		return rdr 
	} 
	return rdr 
} 
 
// findUrlInLine attempts to find the first url embedded in a line 
// of plain text 
// 
// This would be from a file just containing URLS or a "top n domains" 
// from a service like alexa or cisco. 
// 
// e.g. 1,google.com 
func findUrlInLine(line string) *url.URL { 
	// Split on , -- usually from the "top n domains" files 
	parts := strings.Split(line, ",") 
	for i := range parts { 
		parts[i] = strings.TrimSpace(parts[i]) 
		if parts[i] == "" { 
			continue 
		} 
		// return whatever parses as a URL 
		u, err := url.Parse(parts[i]) 
		if err == nil { 
			return u 
		} 
	} 
	return nil 
} 
