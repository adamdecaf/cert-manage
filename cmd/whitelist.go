package cmd

import (
	"fmt"
	// "github.com/adamdecaf/cert-manage/certs"
	"os"
	"path/filepath"
	"strings"
)

// todo: make a backup file, timestamped so we can make multiple if the latest isn't the same
// .backup.20161020HHMMSS
// .backup.20161025HHMMSS
// - compare hash of existing file to latest, if not equal make a new backup

// todo / idea
// Does it make sense to create a `Manager` struct for each type of cert?
// Platforms would need a manage specific to them.

// `Whitelist` deactivates all certs except for those in the given whitelist.
// A non-nil error value will be returned on failure.
func Whitelist(path string, app *string, dryRun bool) *error {
	// Validate path
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || !validWhitelistPath(path) {
		err = fmt.Errorf("Whitelist filepath '%s' doesn't seem valid.", path)
		return &err
	}

	return nil

	// // Whitelist an app's certs
	// if app != nil && *app != "" {
	// 	certs, err := certs.FindCertsForApplication(*app)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	return whitelistCertsForApplication(certs, path)
	// }

	// // Whitelist a platform's certs
	// certs, err := certs.FindCerts()
	// if err != nil {
	// 	return err
	// }
	// return whitelistCertsForPlatform(certs, path)
}

// todo: use dryRun flag
// todo: print certs in whitelist not found
// after diff, remove certs that aren't whitelisted
// `whitelist` performs the diffing of a given set of certs and
// func whitelist(certs []x509.Certificate, path string) error {

// }

// validWhitelistPath verifies that the given whitelist filepath is properly defined
// and exists on the given filesystem.
func validWhitelistPath(path string) bool {
	valid := true
	isFlag := strings.HasPrefix(path, "-")

	if len(path) == 0 || isFlag {
		valid = false
		fmt.Printf("The given whitelist file path '%s' doesn't look correct.\n", path)
		if isFlag {
			fmt.Println("The path looks like a cli flag, -whitelist requires a path to the whitelist file.")
		} else {
			fmt.Println("The given whitelist file path is empty.")
		}
	}

	_, err := os.Stat(path)
	if err != nil {
		valid = false
		fmt.Printf("The path %s doesn't seem to exist.\n", path)
	}

	return valid
}

// if app != nil && *app != "" {
// 	fmt.Println("A")
// 	errors := certs.RemoveCertsForApplication(*app, nil) // nil is for "certs to remove"
// 	if len(errors) != 0 {
// 		fmt.Println(errors)
// 		// todo: return some error
// 	}
// } else {
// 	errors := certs.RemoveCerts(nil) // nil is for "certs to remove"
// 	if len(errors) > 0 {
// 		fmt.Println(errors)
// 		// todo: return some error
// 	}
// }
