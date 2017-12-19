// +build darwin

package test

import (
	"testing"
)

func TestIntegration__date(t *testing.T) {
	cmd := Command("date", "-r", "0").Trim()
	cmd.EqualT(t, "Wed Dec 31 18:00:00 CST 1969")

	inc := cmd.String()
	ans := `Command:
  date -r 0
Output:
  Wed Dec 31 18:00:00 CST 1969`
	if inc != ans {
		t.Errorf("match != ans\n match = '%s'", inc)
	}
}
