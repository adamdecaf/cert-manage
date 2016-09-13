// +build darwin

package certs

import (
	"crypto/x509"
	"os/exec"
)

func FindCerts() ([]*x509.Certificate, error) {
	b, err := exec.Command("security", "find-certificate", "-a", "-p").Output()
	if err != nil {
		return nil, err
	}

	certs, err := ParsePEMIntoCerts(b)
	if err != nil {
		return nil, err
	}
	return certs, nil
}
