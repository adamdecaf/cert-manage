package file

import (
	"io"
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
// CopyFile duplicates the contents of `src` and writes it to a file at `dst` with
// the same permissions and owner/group.
// The parent dirs of `dst` are assumed to exist.
// Adapted From: https://gist.github.com/r0l1/92462b38df26839a3ca324697c8cba04
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	// contents
	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	err = out.Sync()
	if err != nil {
		return err
	}

	// perms
	s, err := os.Stat(src)
	if err != nil {
		return err
	}
	err = os.Chmod(dst, s.Mode())
	if err != nil {
		return err
	}

	return nil
}
