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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

const (
	TempFilePermissions = 0600 // rw for owner only
	TempDirPermissions  = 0700 | os.ModeDir
)

var (
	windowsExecutableSuffixes = []string{".exe", ".cmd", ".bat"}
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

// IsExecutable checks if a given path exists, is a file, not a symlink, and has
// its owner's executable bit set
func IsExecutable(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		name := filepath.Base(s.Name())
		for i := range windowsExecutableSuffixes {
			if strings.HasSuffix(name, windowsExecutableSuffixes[i]) {
				return true
			}
		}
		return false
	}
	return s.Mode()&0100 == 0100
}

// MirrorDir will take a `src` directory and mirror it exactly under `dst` location.
// If no errors occur during the mirroring `nil` is returned, otherwise an non-nil error
// Adapted From: https://gist.github.com/r0l1/92462b38df26839a3ca324697c8cba04
// - Symlinks are copied
func MirrorDir(src, dst string) error {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	// Exit early if `src` isn't a directory
	s, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !s.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}

	// Make `dst`
	_, err = os.Stat(dst)
	if err != nil && !os.IsNotExist(err) {
		return err // some fs error occurred
	}
	err = os.MkdirAll(dst, s.Mode()) // create `dst` with `src` perms

	// copy files, symlinks, and dirs
	items, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}
	for _, item := range items {
		s := filepath.Join(src, item.Name())
		d := filepath.Join(dst, item.Name())

		if item.IsDir() {
			err = MirrorDir(s, d)
			if err != nil {
				return err
			}
			continue
		}

		// Create the symlink by reading the path pointed to in `src`
		// https://stackoverflow.com/questions/18062026/resolve-symlinks-in-go/18062079
		if item.Mode()&os.ModeSymlink != 0 {
			var final string
			final, err = os.Readlink(s)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			err = os.Symlink(final, d)
			if err != nil {
				return err
			}
		} else {
			err = CopyFile(s, d)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// CopyFile duplicates the contents of `src` and writes it to a file at `dst` with the same permissions
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

// SudoCopyFile attempts to copy a file (and wraps CopyFile), but if required will escalate to
// higher permissions in order to copy a file.
func SudoCopyFile(src, dst string) error {
	// Clean both paths
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	// quit if the paths look weird, or src doesn't exist
	ssrc, err := os.Stat(src)
	if err != nil {
		return err
	}
	if ssrc.Size() == 0 {
		return fmt.Errorf("%q appears to be an empty file", src)
	}
	// Paths of just / or C:\
	// Clean(p) returns '.' if p is blank
	if utf8.RuneCountInString(src) <= 3 || utf8.RuneCountInString(dst) <= 3 {
		return fmt.Errorf("either src=%q and dst=%q doesn't seem like a valid path", src, dst)
	}

	// Drop down to platform specific file copy (with elevated permissions)
	return execCopy(src, dst)
}
