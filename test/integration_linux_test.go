// +build linux

package test

import (
	"testing"
)

func TestIntegration__date(t *testing.T) {
	cmd := Command("date", "--date='@0'").Trim()
	cmd.EqualT(t, "Thu Jan  1 00:00:00 UTC 1970")
}
