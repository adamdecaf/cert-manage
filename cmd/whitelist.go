package cmd

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
)

// `Whitelist` deactivates all certs except for those in the given
// whitelist.
func Whitelist(path string, app *string) {
	// todo: find all certs, diff, and remove
	// c, err := certs.FindCerts()

	// todo: print certs in whitelist not found

	// after diff, remove certs that aren't whitelisted
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
