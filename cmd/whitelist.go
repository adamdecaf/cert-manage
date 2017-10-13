package cmd

// Whitelist steps
// 1. Make a backup
// 2. Diff to find removable certs
// 3. Remove removable certs
// 4. Print some summary/status of certificates?

// TODO(adam): -dry-run flag
// TOOD(adam): print certs in whitelist not found

import (
	"github.com/adamdecaf/cert-manage/store"
	"github.com/adamdecaf/cert-manage/whitelist"
)

func WhitelistForApp(app, whpath, format string) error {
	// grab existing
	st, err := store.ForApp(app)
	if err != nil {
		return err
	}
	certs, err := st.List()
	if err != nil {
		return err
	}

	// load whitelist
	items, err := whitelist.FromFile(whpath)
	if err != nil {
		return err
	}

	// diff
	removable := whitelist.Removable(certs, items)
	err = st.Remove(removable)
	if err != nil {
		return err
	}

	return nil
}

func WhitelistForPlatform(whpath, format string) error {
	// grab existing
	st := store.Platform()
	certs, err := st.List()
	if err != nil {
		return err
	}

	// load whitelist
	items, err := whitelist.FromFile(whpath)
	if err != nil {
		return err
	}

	// diff
	removable := whitelist.Removable(certs, items)
	err = st.Remove(removable)
	if err != nil {
		return err
	}

	return nil
}

// func WhitelistCertsForPlatform(whitelist string, dryRun bool, format string) error {
// 	wh, err := certs.FromFile(whitelist)
// 	if err != nil {
// 		return fmt.Errorf("Whitelist filepath '%s' doesn't seem valid.", whitelist)
// 	}

// 	// Whitelist a platform's certs
// 	certificates, err := certs.FindCerts()
// 	if err != nil {
// 		return err
// 	}

// 	// Filter certs
// 	removable := certs.Filter(certificates, wh)

// 	if dryRun {
// 		fmt.Println("These certs will be removed.")
// 		PrintCerts(removable, format)
// 	}

// 	errors := certs.RemoveCerts(removable)
// 	if len(errors) > 0 {
// 		for _,e := range errors {
// 			fmt.Println(e)
// 		}
// 		return fmt.Errorf("Errors when trying to whitelist certs")
// 	}

// 	return nil
// }

// func WhitelistCertsForApp(whitelist, app string, dryRun bool, format string) error {
// 	// if !validWhitelistPath(whitelist) {
// 	// 	return fmt.Errorf("Whitelist filepath '%s' doesn't seem valid.", whitelist)
// 	// }

// 	// // Whitelist an app's certs
// 	// if app != nil && *app != "" {
// 	// 	certs, err := certs.FindCertsForApplication(*app)
// 	// 	if err != nil {
// 	// 		return err
// 	// 	}
// 	// 	return whitelistCertsForApplication(certs, path)
// 	// }

// 	// errors := certs.RemoveCertsForApplication(*app, nil) // nil is for "certs to remove"
// 	// if len(errors) != 0 {
// 	// 	fmt.Println(errors)
// 	// 	// todo: return some error
// 	// }

// 	return nil
// }
