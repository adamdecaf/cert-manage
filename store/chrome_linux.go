// +build linux

package store

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/tools/file"
	"path/filepath"
)

func chromeCertdbLocations() []string {
	uhome := file.HomeDir()
	if uhome == "" {
		if debug {
			fmt.Println("store/chrome: unable to find user's home dir")
		}
		return nil
	}

	return []string{
		filepath.Join(uhome, ".pki/nssdb"),
	}
}

// On linux chrome uses NSS
// https://www.chromium.org/Home/chromium-security/root-ca-policy
func ChromeStore() Store {
	suggestions := collectNssSuggestions(chromeCertdbLocations())
	return NssStore("chrome", suggestions)
}
