package tools

import (
	"os"
	"path/filepath"
	"strings"
)

// FileExists expands the given path and verifies a file located at the given path.
func FileExists(path string) bool {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return false
	}

	_, err = os.Stat(path)
	return err == nil
}
