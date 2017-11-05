// +build linux

package store

import (
	"runtime"
	"testing"
)

func StoreLinux__cadir(t *testing.T) {
	// just grab the linuxStore and make sure it has a cadir member
	s, ok := platform().(linuxStore)
	if !ok {
		t.Error("error casting to linuxStore")
	}
	if s.ca.empty() {
		t.Errorf("no cadir found on platform: %s", runtime.GOOS)
	}
}
