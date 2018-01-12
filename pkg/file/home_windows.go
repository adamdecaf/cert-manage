// +build windows

package file

import (
	"os"
)

func homeDir() string {
	return os.Getenv("USERPROFILE")
}
