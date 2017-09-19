// +build windows

package fetch

import (
	"crypto/x509"
	"fmt"
	"os/exec"
)

// call into
// https://msdn.microsoft.com/en-us/library/e78byta0(v=vs.110).aspx

// Platform returns a slice of certificates installed on the running machine
func Platform() ([]*x509.Certificate, error) {
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
