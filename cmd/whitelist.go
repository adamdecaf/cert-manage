package cmd

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
	"strings"
)

// `Whitelist` deactivates all certs except for those in the given
// whitelist.
func Whitelist(path string, app *string) {
	// todo: find all certs, diff, and remove
	//   print certs in whitelist not found?

	// Check if the path looks like a cli flag.
	isFlag := strings.HasPrefix(path, "-")
	if len(path) == 0 || isFlag {
		fmt.Printf("The given whitelist file path '%s' doesn't look correct.\n", path)
		if isFlag {
			fmt.Println("The path looks like a cli flag, -whitelist requires a path to the whitelist file.")
		} else {
			fmt.Println("The given whitelist file path is empty.")
		}
	}

	if app != nil && *app != "" {
		fmt.Println("A")
		errors := certs.RemoveCertsForApplication(*app, nil)
		if len(errors) != 0 {
			fmt.Println(errors)
		}
	} else {
		errors := certs.RemoveCerts(nil)
		if len(errors) > 0 {
			fmt.Println(errors)
		}
	}

	return
}
