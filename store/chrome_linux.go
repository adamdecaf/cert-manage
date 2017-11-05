// +build linux

package store

import (
	"fmt"
	"os"
	"path/filepath"
)

func chromeCertdbLocations() []string {
	uhome := os.Getenv("HOME")
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
