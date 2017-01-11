package cmd

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
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
func WhitelistCertsForPlatform(whitelist string, dryRun bool, format string) error {
	wh, err := certs.FromFile(whitelist)
	if err != nil {
		return fmt.Errorf("Whitelist filepath '%s' doesn't seem valid.", whitelist)
	}

	// Whitelist a platform's certs
	certificates, err := certs.FindCerts()
	if err != nil {
		return err
	}

	// figure out which certs to keep
	keep := certs.Keep(certificates, wh)

	if dryRun {
		fmt.Println("These certs will be kept.")
		PrintCerts(keep, format)
	}

	// errors := certs.RemoveCerts(nil) // nil is for "certs to remove"
	// if len(errors) > 0 {
	// 	fmt.Println(errors)
	// 	// todo: return some error
	// }

	return nil
}

//
func WhitelistCertsForApp(whitelist, app string, dryRun bool, format string) error {
	// if !validWhitelistPath(whitelist) {
	// 	return fmt.Errorf("Whitelist filepath '%s' doesn't seem valid.", whitelist)
	// }

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
