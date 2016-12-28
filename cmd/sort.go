package cmd

import (
	"strings"
)

// IStringSlice is a case-insensitive string sorting implementation
type iStringSlice []string
func (p iStringSlice) Len() int           { return len(p) }
func (p iStringSlice) Less(i, j int) bool { return strings.ToLower(p[i]) < strings.ToLower(p[j]) }
func (p iStringSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
