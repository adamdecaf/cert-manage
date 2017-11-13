// +build linux darwin

package file

import (
	"os"
)

func homeDir() string {
	return os.Getenv("HOME")
}
