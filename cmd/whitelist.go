package cmd

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
	"os"
	"path/filepath"
	"strings"
)

// `Whitelist` deactivates all certs except for those in the given
// whitelist.
// A non-nil error value will be returned on failure.
func Whitelist(path string, app *string) *error {
	// Validate path
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || !validWhitelistPath(path) {
		err = fmt.Errorf("Whitelist filepath '%s' doesn't seem valid.", path)
		return &err
	}

	// todo: find all certs, diff, and remove
	// c, err := certs.FindCerts()

	// todo: print certs in whitelist not found

	// after diff, remove certs that aren't whitelisted
	if app != nil && *app != "" {
		fmt.Println("A")
		errors := certs.RemoveCertsForApplication(*app, nil)
		if len(errors) != 0 {
			fmt.Println(errors)
			// todo: return some error
		}
	} else {
		errors := certs.RemoveCerts(nil)
		if len(errors) > 0 {
			fmt.Println(errors)
			// todo: return some error
		}
	}

	return nil
}

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
