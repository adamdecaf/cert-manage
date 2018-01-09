package test

import (
	"testing"
)

func TestAlpine(t *testing.T) {
	total := "151"
	// total, after := "151", "5" // os specific values, will change
	img := Dockerfile("envs/alpine")
	img.CertManage("list", "-count", "|", "grep", total)
	img.SuccessT(t)
}

// # Make a backup
// /bin/cert-manage backup

// # Quick check
// ls -1 /usr/share/ca-certificates/* | wc -l | grep $total
// ls -1 /usr/share/ca-certificates.backup/* | wc -l | grep $total

// # Whitelist and verify
// /bin/cert-manage whitelist -file /whitelist.json
// /bin/cert-manage list -count | grep $after

// # Restore
// /bin/cert-manage restore
// /bin/cert-manage list -count | grep $total

// echo "Alpine 3.7 Passed"
