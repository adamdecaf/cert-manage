package cmd

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/pkg/store"
)

func BackupForApp(app string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	err = s.Backup()
	if err == nil {
		fmt.Println("Backup completed successfully")
	}
	return err
}

func BackupForPlatform() error {
	err := store.Platform().Backup()
	if err == nil {
		fmt.Println("Backup completed successfully")
	}
	return err
}
