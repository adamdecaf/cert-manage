// +build linux

package test

import (
	"testing"
)

func TestIntegration__date(t *testing.T) {
	cmd := Command("date", "-u", "--date", "@0").Trim()
	cmd.EqualT(t, "Thu Jan  1 00:00:00 UTC 1970")
	cmd.SuccessT(t)
}

func TestIntegration__unknown(t *testing.T) {
	cmd := CertManage("other").Trim()
	cmd.FailedT(t)
}

func TestIntegration__list(t *testing.T) {
	cmd := CertManage("list", "-count").Trim()
	cmd.CmpIntF(t, func(i int) bool { return i > 1 })
	cmd.SuccessT(t)
}

func TestIntegration__backup(t *testing.T) {
	cmd := CertManage("backup").Trim()
	if inCI() {
		// Travis-CI current must have something (openssl?) installed which adds
		// extra directories/certs
		// For now let's just mark this as pending in CI
		// TODO: https://github.com/adamdecaf/cert-manage/issues/105
		cmd.PendingT(t, "something wonky with 'ca-certificates.backup/.mozilla' dir")
	} else {
		cmd.EqualT(t, "Backup completed successfully")
	}
	cmd.SuccessT(t)
}

// TODO(adam): Need to run -whitelist and -restore
