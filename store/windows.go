// +build windows

package store

import (
	"crypto/x509"
	"fmt"
	"os/exec"
)

// Docs:
// - https://msdn.microsoft.com/en-us/library/e78byta0(v=vs.110).aspx

type windowsStore struct{}

func platform() Store {
	return windowsStore{}
}

func (s windowsStore) List() ([]*x509.Certificate, error) {
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

// TODO(adam): impl
func (s windowsStore) Remove([]*x509.Certificate) error {
	return nil
}
