package server

import (
	"testing"
)

func TestUIServer__getPort(t *testing.T) {
	n := getPort()
	if n < 1024 && n > 2<<15 {
		t.Errorf("%d is an invalid port", n)
	}
}
