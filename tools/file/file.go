package file

import (
	"os"
	"path/filepath"
	"strings"
)

// Exists returns true if the give path represents a file or directory
func Exists(path string) bool {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return false
	}

	_, err = os.Stat(path)
	return err == nil
}
