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
