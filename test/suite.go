package test

import (
	"fmt"
	"testing"
)

func linuxSuite(t *testing.T, img *dockerfile, total, after string) {
	if debug {
		fmt.Println("Linux start")
	}

	// List
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

	if debug {
		fmt.Println("Linux end")
	}
}

func javaSuite(t *testing.T, img *dockerfile, total, after string) {
	if debug {
		fmt.Println("Java start")
	}

	// List
	img.CertManage("list", "-count", "-app", "java", "|", "grep", total)

	img.SuccessT(t)

	if debug {
		fmt.Println("Java end")
	}
}
