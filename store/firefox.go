package store

import (
	"fmt"
	"os"
	"path/filepath"
)

// returns a slice of "suggestions" for where cert8.db files live.
// The idea of tihs slice is to generalize over randomly named directories
// (how firefox names profiles) and handle user-specific filepaths
func firefoxCertdbLocations() []string {
	uhome := os.Getenv("HOME")
	if uhome == "" {
		if debug {
			fmt.Println("unable to find user's home dir")
		}
		return nil
	}

	return []string{
		filepath.Join(uhome, ".mozilla/firefox/*.default"),                              // Linux
		filepath.Join(uhome, "/Library/Application Support/Firefox/Profiles/*.default"), // darwin
	}
}

func FirefoxStore() Store {
	suggestions := collectNssSuggestions(firefoxCertdbLocations())
	return NssStore("firefox", suggestions)
}
