package cmd

import (
	"github.com/adamdecaf/cert-manage/store"
)

func BackupForApp(app string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	return s.Backup()
}

func BackupForPlatform() error {
	return store.Platform().Backup()
}
