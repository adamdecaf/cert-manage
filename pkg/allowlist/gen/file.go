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
	"unicode"

	"github.com/adamdecaf/trustprune/pkg/file"
)

var (
	gzipHeader = []byte{0x1f, 0x8b}
)

// FromFile reads a text file and grabs urls separated by newlines.
// Lines may be full URLs, or Tranco/Alexa/Cisco-style "rank,domain" CSV rows
// (https:// is prefixed onto the domain). Gzip-compressed files are accepted.
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
	defer func() { _ = fd.Close() }()
	var res []*url.URL
	rdr := bufio.NewScanner(decodeIfGzipped(fd))

	for rdr.Scan() {
		if u := findURLInLine(rdr.Text()); u != nil {
			res = append(res, u)
		}
	}
	if err := rdr.Err(); err != nil {
		return nil, err
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

// findURLInLine attempts to find the first url embedded in a line
// of plain text.
//
// Supported forms:
//   - full URLs (https://example.com)
//   - Tranco/Alexa/Cisco "rank,domain" CSV rows (1,google.com)
//
// Bare domains without a scheme are not accepted outside the CSV form.
func findURLInLine(line string) *url.URL {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	if domain, ok := parseRankDomain(line); ok {
		return httpsURL(domain)
	}

	u, err := url.Parse(line)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	return u
}

// parseRankDomain recognizes "rank,domain" rows used by Tranco, Alexa, and Cisco.
// The rank must be a positive integer; the domain is the remainder after the first comma.
func parseRankDomain(line string) (domain string, ok bool) {
	rank, domain, found := strings.Cut(line, ",")
	if !found {
		return "", false
	}
	rank = strings.TrimSpace(rank)
	domain = strings.TrimSpace(domain)
	if rank == "" || domain == "" {
		return "", false
	}
	for _, r := range rank {
		if !unicode.IsDigit(r) {
			return "", false
		}
	}
	// Reject domains that already look like a URL with a scheme; those belong
	// on their own line as full URLs.
	if strings.Contains(domain, "://") {
		return "", false
	}
	return domain, true
}

func httpsURL(domain string) *url.URL {
	u, err := url.Parse("https://" + domain)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}
