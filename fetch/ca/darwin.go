package ca

import (
	"crypto/x509"
	"github.com/adamdecaf/cert-manage/tools"
	"os/exec"
)

// Docs
// - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html

// todo: find and show each cert's trust status

// TODO(adam): Error if we're running this on non-darwin?

func Darwin() ([]*x509.Certificate, error) {
	b, err := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p").Output()
	if err != nil {
		return nil, err
	}

	certs, err := tools.ParsePEMIntoCerts(b)
	if err != nil {
		return nil, err
	}
	return certs, nil
}
