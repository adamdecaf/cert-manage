package store

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/pkg/file"
	"path/filepath"
)

// returns a slice of "suggestions" for where cert8.db files live.
// The idea of tihs slice is to generalize over randomly named directories
// (how firefox names profiles) and handle user-specific filepaths
func firefoxCertdbLocations() []cert8db {
	uhome := file.HomeDir()
	if uhome == "" {
		if debug {
			fmt.Println("store/firefox: unable to find user's home dir")
		}
		return nil
	}

	paths := []cert8db{
		cert8db(filepath.Join(uhome, ".mozilla/firefox/*.default")),                              // Linux
		cert8db(filepath.Join(uhome, "/Library/Application Support/Firefox/Profiles/*.default")), // darwin
	}

	return paths
}

func FirefoxStore() Store {
	suggestions := firefoxCertdbLocations()
	found := locateCert8db(suggestions)
	return NssStore("firefox", suggestions, found)
}
