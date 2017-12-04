package cmd

import (
	"github.com/adamdecaf/cert-manage/store"
	"github.com/adamdecaf/cert-manage/whitelist"
)

func WhitelistForApp(app, whpath string, cfg *Config) error {
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

	certs, err := st.Remove(wh, cfg.DryRun)
	if err != nil {
		return err
	}

	if cfg.DryRun {
		printCerts(certs, cfg.Format)
	}

	return nil
}

func WhitelistForPlatform(whpath string, cfg *Config) error {
	// load whitelist
	wh, err := whitelist.FromFile(whpath)
	if err != nil {
		return err
	}

	// diff
	st := store.Platform()
	certs, err := st.Remove(wh, cfg.DryRun)
	if err != nil {
		return err
	}

	if cfg.DryRun {
		printCerts(certs, cfg.Format)
	}

	return nil
}
