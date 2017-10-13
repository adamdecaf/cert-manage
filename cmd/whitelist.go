package cmd

// Whitelist steps
// - [ ] Make a backup
// - [x] Diff to find removable certs
// - [x] Remove removable certs
// - [ ] Print some summary/status of certificates?

// TODO(adam): -dry-run flag
// TOOD(adam): print certs in whitelist not found

import (
	"github.com/adamdecaf/cert-manage/store"
	"github.com/adamdecaf/cert-manage/whitelist"
)

func WhitelistForApp(app, whpath, format string) error {
	// load whitelist
	wh, err := whitelist.FromFile(whpath)
	if err != nil {
		return err
	}

	// diff
	st, err := store.ForApp(app)
	if err != nil {
		return err
	}
	err = st.Remove(wh)
	if err != nil {
		return err
	}

	return nil
}

func WhitelistForPlatform(whpath, format string) error {
	// load whitelist
	wh, err := whitelist.FromFile(whpath)
	if err != nil {
		return err
	}

	// diff
	st := store.Platform()
	err = st.Remove(wh)
	if err != nil {
		return err
	}

	return nil
}
