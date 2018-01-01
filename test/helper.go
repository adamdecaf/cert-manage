package test

import (
	"os"
	"testing"
)

// Check if we're online or not, via:
// - localhost icmp ping
// - TRAVIS_OS_NAME env var
func online(t *testing.T) bool {
	t.Helper()

	cmd := Command("ping", "-c1", "localhost").Trim()
	if len(cmd.output) == 0 { // no output, check for error
		defer cmd.SuccessT(t)
	}
	return cmd.Success() || inCI()
}

func inCI() bool {
	return os.Getenv("TRAVIS_OS_NAME") != ""
}
