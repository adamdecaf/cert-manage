// +build windows

package store

import (
	"crypto/x509"
	"fmt"
	"os/exec"

	"github.com/adamdecaf/cert-manage/whitelist"
)

// Docs:
// https://msdn.microsoft.com/en-us/library/e78byta0(v=vs.110).aspx
// https://social.technet.microsoft.com/wiki/contents/articles/31633.microsoft-trusted-root-program-requirements.aspx

// Certificate store locations:
// - https://superuser.com/questions/411909/where-is-the-certificate-folder-in-windows-7
// - https://msdn.microsoft.com/en-us/library/windows/desktop/aa388136(v=vs.85).aspx

type windowsStore struct{}

func platform() Store {
	return windowsStore{}
}

func (s windowsStore) Backup() error {
	return nil
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

func (s windowsStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s windowsStore) Restore(where string) error {
	return nil
}
