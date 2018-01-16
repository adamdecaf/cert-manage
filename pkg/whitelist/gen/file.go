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
