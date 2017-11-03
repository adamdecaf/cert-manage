package store

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

var (
	cert8Filename = "cert8.db"
)

// returns a slice of "suggestions" for where cert8.db files live.
// The idea of tihs slice is to generalize over randomly named directories
// (how firefox names profiles) and handle user-specific filepaths
func cert8dbSuggestions() []string {
	u, err := user.Current()
	if err != nil {
		return nil
	}

	return []string{
		filepath.Join(u.HomeDir, "/Library/Application Support/Firefox/Profiles/*.default"), // darwin
	}
}

func firefoxProfileDiscoverer() []cert8db {
	sugs := cert8dbSuggestions()

	kept := make([]cert8db, 0)
	for i := range sugs {
		// Glob and find a cert8.db file
		matches, err := filepath.Glob(sugs[i])
		if err != nil {
			if debug {
				fmt.Println(err.Error())
			}
			return nil
		}

		// Accumulate dirs with a cert8.db file
		for j := range matches {
			if containsCert8db(matches[j]) {
				kept = append(kept, cert8db(matches[j]))
			}
		}
	}
	return kept
}

func containsCert8db(p string) bool {
	s, err := os.Stat(filepath.Join(p, cert8Filename))
	if err != nil {
		if debug {
			fmt.Println(err.Error())
		}
		return false
	}
	return s.Size() > 0
}

func FirefoxStore() Store {
	return nssStore{
		paths: firefoxProfileDiscoverer(),
	}
}
