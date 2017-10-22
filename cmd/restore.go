package cmd

import (
	"github.com/adamdecaf/cert-manage/store"
)

func RestoreForApp(app, path string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	return s.Restore(path)
}

func RestoreForPlatform(path string) error {
	return store.Platform().Restore(path)
}
