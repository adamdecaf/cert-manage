package test

import (
	"fmt"
	"testing"
)

func TestDebian(t *testing.T) {
	total, after := "166", "5" // os specific values, will change

	img := Dockerfile("envs/debian")
	img.CertManage("list", "-count", "|", "grep", total)
	// Backup
	img.CertManage("backup")
	img.RunSplit(fmt.Sprintf("ls -1 /usr/share/ca-certificates/* | wc -l | grep %s", total))
	img.RunSplit(fmt.Sprintf("ls -1 /usr/share/ca-certificates.backup/* | wc -l | grep %s", total))
	// Whitelist
	img.CertManage("whitelist", "-file", "/whitelist.json")
	img.CertManage("list", "-count", "|", "grep", after)
	// Restore
	img.CertManage("restore")
	img.CertManage("list", "-count", "|", "grep", total)
	img.SuccessT(t)
}
