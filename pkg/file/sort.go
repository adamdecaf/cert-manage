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
