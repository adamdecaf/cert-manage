// +build linux

package test

import (
	"os"
	"testing"
)

func TestIntegration__date(t *testing.T) {
	cmd := Command("date", "-u", "--date", "@0").Trim()
	cmd.EqualT(t, "Thu Jan  1 00:00:00 UTC 1970")
}

func TestIntegration__unknown(t *testing.T) {
	cmd := CertManage("other").Trim()
	cmd.FailedT(t)
}

func TestIntegration__list(t *testing.T) {
	cmd := CertManage("list", "-count").Trim()
	cmd.CmpFnT(t, func(i int) bool { return i > 1 })
}

func TestIntegration__backup(t *testing.T) {
	cmd := CertManage("backup").Trim()
	cmd.EqualT(t, "Backup completed successfully")
}

// TODO(adam): Need to run -whitelist and -restore

func TestIntegration__java(t *testing.T) {
	if os.Getenv("JAVA_HOME") == "" {
		t.Skip("java isn't installed/setup")
	}

	cmd := CertManage("list", "-count", "-app", "java").Trim()
	cmd.SuccessT(t)
	cmd.CmpFnT(t, func(i int) bool { return i > 1 })
}
