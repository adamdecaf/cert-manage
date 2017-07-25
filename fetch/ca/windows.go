package ca

import (
	"crypto/x509"
	"fmt"
	"os/exec"
)

// call into
// https://msdn.microsoft.com/en-us/library/e78byta0(v=vs.110).aspx

// To list certs, run `certmgr.msc` in a prompt..so os/exec ?

// TODO(adam): Error if we're running this on non-windows?

// Windows returns a slice of certificates installed on the running machine
func Windows() ([]*x509.Certificate, error) {
	stores := []string{"My", "AuthRoot", "Root", "Trust", "CA", "Disallowed"}
	for i := range stores {
		fmt.Println(stores[i])
		// b, err := exec.Command("cmd", "certmgr.exe", "/s", "-s", stores[i]).Output()
		b, err := exec.Command("certmgr", "-s", stores[i]).Output()
		if err != nil {
			fmt.Println("Error: ", err)
		}
		fmt.Println(string(b))
	}

	return nil, nil
}
