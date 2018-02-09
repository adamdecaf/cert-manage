package test

import (
	"fmt"
	"strconv"
	"testing"
)

type cfg struct {
	total, after string

	curlExitCode string
}

func (c *cfg) failIfEmpty(t *testing.T) {
	t.Helper()

	if c.total == "" || c.after == "" {
		t.Fatalf("total=%q or after=%q is blank", c.total, c.after)
	}
	if c.curlExitCode == "" {
		t.Fatal("missing curlExitCode")
	}
}

func linuxSuite(t *testing.T, img *dockerfile, config cfg) {
	config.failIfEmpty(t)

	if debug {
		fmt.Println("Linux start")
	}

	// List
	img.CertManage("list", "-count", "|", "grep", config.total)
	// Backup
	img.CertManage("backup")
	img.RunSplit(fmt.Sprintf("ls -1 /usr/share/ca-certificates/* | wc -l | grep %s", config.total))
	img.RunSplit(fmt.Sprintf("ls -1 /usr/share/ca-certificates.backup/* | wc -l | grep %s", config.total))
	// Whitelist
	img.CertManage("whitelist", "-file", "/whitelist.json")
	img.CertManage("list", "-count", "|", "grep", config.after)
	// Verify google.com fails to load
	img.ExitCode(config.curlExitCode, "curl", "-I", "https://www.google.com/images/branding/product/ico/googleg_lodp.ico")
	// Restore
	img.CertManage("restore")
	// Verify Restore
	img.CertManage("list", "-count", "|", "grep", config.total)
	img.Run("curl", "-I", "https://www.google.com/images/branding/product/ico/googleg_lodp.ico")
	// Add certificate
	img.CertManage("add", "-file", "/localcert.pem")
	img.CertManage("list", "-count", "|", "grep", incr(config.total))
	img.SuccessT(t)

	if debug {
		fmt.Println("Linux end")
	}
}

func javaSuite(t *testing.T, img *dockerfile, total, after string) {
	if total == "" || after == "" {
		t.Fatalf("total=%q or after=%q is blank", total, after)
	}
	if debug {
		fmt.Println("Java start")
	}

	// List
	img.CertManage("list", "-count", "-app", "java", "|", "grep", total)
	// Backup
	img.CertManage("backup", "-app", "java")
	img.RunSplit("ls -1 ~/.cert-manage/java | wc -l | grep 1")
	// Check java
	img.RunSplit("cd / && java Download")
	// Whitelist java
	img.CertManage("whitelist", "-file", "/whitelist.json", "-app", "java")
	img.CertManage("list", "-app", "java", "-count", "|", "grep", after)
	// Verify google.com fails to load
	img.Run("cd", "/")
	img.ShouldFail("java", "Download", "2>&1", "|", "grep", `'PKIX path building failed'`)
	// Restore
	img.CertManage("restore", "-app", "java")
	img.CertManage("list", "-app", "java", "-count", "|", "grep", total)
	// Verify Restore
	img.RunSplit("cd / && java Download")
	// Add certificate
	img.CertManage("add", "-file", "/localcert.pem", "-app", "java")
	img.CertManage("list", "-count", "-app", "java", "|", "grep", incr(total))
	img.SuccessT(t)

	if debug {
		fmt.Println("Java end")
	}
}

func opensslSuite(t *testing.T, img *dockerfile, config cfg) {
	config.failIfEmpty(t)

	if debug {
		fmt.Println("openssl start")
	}

	// List
	img.CertManage("list", "-app", "openssl", "-count", "|", "grep", config.total)
	// Backup
	img.CertManage("backup", "-app", "openssl") // TODO(adam): verify
	// Whitelist
	img.CertManage("whitelist", "-app", "openssl", "-file", "/whitelist.json")
	img.CertManage("list", "-app", "openssl", "-count", "|", "grep", config.after)
	// Verify google.com fails to load
	// TODO(adam): automated way to ensure curl uses openssl?
	img.ExitCode(config.curlExitCode, "curl", "-I", "https://www.google.com/images/branding/product/ico/googleg_lodp.ico")
	// Restore
	img.CertManage("restore", "-app", "openssl")
	// Verify Restore
	img.CertManage("list", "-app", "openssl", "-count", "|", "grep", config.total)
	// TODO(adam): automated way to ensure curl uses openssl?
	img.Run("curl", "-I", "https://www.google.com/images/branding/product/ico/googleg_lodp.ico")
	// Add certificate
	img.CertManage("add", "-app", "openssl", "-file", "/localcert.pem")
	img.CertManage("list", "-app", "openssl", "-count", "|", "grep", incr(config.total))
	img.SuccessT(t)

	if debug {
		fmt.Println("openssl end")
	}
}

func incr(in string) string {
	n, err := strconv.Atoi(in)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%d", n+1)
}
