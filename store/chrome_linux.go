// +build linux

package store

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/tools/file"
	"path/filepath"
)

func chromeCertdbLocations() []cert8db {
	uhome := file.HomeDir()
	if uhome == "" {
		if debug {
			fmt.Println("store/chrome: unable to find user's home dir")
		}
		return nil
	}

	return []cert8db{
		cert8db(filepath.Join(uhome, ".pki/nssdb")),
	}
}

// On linux chrome uses NSS
// https://www.chromium.org/Home/chromium-security/root-ca-policy
func ChromeStore() Store {
	suggestions := chromeCertdbLocations()
	found := locateCert8db(suggestions)
	return NssStore("chrome", suggestions, found)
}
