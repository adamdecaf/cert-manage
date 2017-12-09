package cmd

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/store"
)

func RestoreForApp(app, path string) error {
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}
	err = s.Restore(path)
	if err == nil {
		fmt.Println("Restore completed successfully")
	}
	return err
}

func RestoreForPlatform(path string) error {
	err := store.Platform().Restore(path)
	if err == nil {
		fmt.Println("Restore completed successfully")
	}
	return err
}
