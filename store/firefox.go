package store

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/tools/file"
	"path/filepath"
)

// returns a slice of "suggestions" for where cert8.db files live.
// The idea of tihs slice is to generalize over randomly named directories
// (how firefox names profiles) and handle user-specific filepaths
func firefoxCertdbLocations() []string {
	uhome := file.HomeDir()
	if uhome == "" {
		if debug {
			fmt.Println("store/firefox: unable to find user's home dir")
		}
		return nil
	}

	paths := []string{
		filepath.Join(uhome, ".mozilla/firefox/*.default"),                              // Linux
		filepath.Join(uhome, "/Library/Application Support/Firefox/Profiles/*.default"), // darwin
	}

	// TODO(adam): windows support
	// Try and add windows path
	// https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data
	// paths = append(paths, filepath.Join(appdata, `Mozilla\Firefox\Profiles`))

	return paths
}

func FirefoxStore() Store {
	suggestions := collectNssSuggestions(firefoxCertdbLocations())
	return NssStore("firefox", suggestions)
}
