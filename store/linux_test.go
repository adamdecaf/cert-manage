// +build linux

package store

import (
	"runtime"
	"testing"
)

func StoreLinux__cadir(t *testing.T) {
	// just grab the linuxStore and make sure it has a cadir member
	s := platform()
	if s.ca == nil || s.ca.empty() {
		t.Errorf("no cadir found on platform: %s", runtime.GOOS)
	}
}
