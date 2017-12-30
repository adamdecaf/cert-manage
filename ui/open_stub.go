// +build linux windows

package ui

import (
	"fmt"
	"runtime"
)

func Open() error {
	fmt.Printf("WARN: ui not supported on %s yet\n", runtime.GOOS)
	return nil
}
