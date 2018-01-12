package cmd

import (
	"fmt"

	"github.com/adamdecaf/cert-manage/pkg/store"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

func WhitelistForApp(app, whpath string) error {
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

	fmt.Println("Whitelist completed successfully")
	return nil
}

func WhitelistForPlatform(whpath string) error {
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

	fmt.Println("Whitelist completed successfully")
	return nil
}
