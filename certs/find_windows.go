// +build windows

package certs

import (
	"crypto/x509"
	// "os/exec"
)

// call into
// https://msdn.microsoft.com/en-us/library/e78byta0(v=vs.110).aspx

// To list certs, run `certmgr.msc` in a prompt..so os/exec ?

func FindCerts() ([]*x509.Certificate, error) {
	return nil, nil
}
