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

// todo: use dryRun flag
// todo: print certs in whitelist not found
// after diff, remove certs that aren't whitelisted
// `whitelist` performs the diffing of a given set of certs and

//
func WhitelistCertsForPlatform(whitelist string, dryRun bool) error {
	if !validWhitelistPath(whitelist) {
		return fmt.Errorf("Whitelist filepath '%s' doesn't seem valid.", whitelist)
	}

	// // Whitelist a platform's certs
	// certs, err := certs.FindCerts()
	// if err != nil {
	// 	return err
	// }
	// return whitelistCertsForPlatform(certs, path)

	// errors := certs.RemoveCerts(nil) // nil is for "certs to remove"
	// if len(errors) > 0 {
	// 	fmt.Println(errors)
	// 	// todo: return some error
	// }

	return nil
}

//
func WhitelistCertsForApp(whitelist, app string, dryRun bool) error {
	if !validWhitelistPath(whitelist) {
		return fmt.Errorf("Whitelist filepath '%s' doesn't seem valid.", whitelist)
	}

	// // Whitelist an app's certs
	// if app != nil && *app != "" {
	// 	certs, err := certs.FindCertsForApplication(*app)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	return whitelistCertsForApplication(certs, path)
	// }

	// errors := certs.RemoveCertsForApplication(*app, nil) // nil is for "certs to remove"
	// if len(errors) != 0 {
	// 	fmt.Println(errors)
	// 	// todo: return some error
	// }

	return nil
}

// validWhitelistPath verifies that the given whitelist filepath is properly defined
// and exists on the given filesystem.
func validWhitelistPath(path string) bool {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		fmt.Printf("expanding the path failed with: %s\n", err)
		return false
	}

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

	_, err = os.Stat(path)
	if err != nil {
		valid = false
		fmt.Printf("The path %s doesn't seem to exist.\n", path)
	}

	return valid
}
