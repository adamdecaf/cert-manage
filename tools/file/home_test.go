package file

import (
	"testing"
)

func TestFile__homeDir(t *testing.T) {
	home := HomeDir()
	if home == "" {
		t.Fatalf("%s shouldn't be blank", home)
	}
}
