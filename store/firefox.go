package store

import (
	"os/user"
	"path/filepath"
)

// returns a slice of "suggestions" for where cert8.db files live.
// The idea of tihs slice is to generalize over randomly named directories
// (how firefox names profiles) and handle user-specific filepaths
func ffCert8Locations() []string {
	u, err := user.Current()
	if err != nil {
		return nil
	}

	return []string{
		filepath.Join(u.HomeDir, "/Library/Application Support/Firefox/Profiles/*.default"), // darwin
	}
}

func FirefoxStore() Store {
	suggestions := collectNssSuggestions(ffCert8Locations())
	return nssStore{
		paths: suggestions,
	}
}
