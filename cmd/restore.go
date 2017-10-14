package cmd

import (
	"github.com/adamdecaf/cert-manage/store"
)

func RestoreForApp(app string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	return s.Restore()
}

func RestoreForPlatform() error {
	return store.Platform().Restore()
}
