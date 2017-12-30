package ui

import (
	"github.com/adamdecaf/cert-manage/ui/server"
)

// TODO(adam): This will need to shake out better
func DefaultFormat() string {
	return "web"
}
func GetFormats() []string {
	return []string{DefaultFormat(), "none"}
}

// Wrapper on Open() and server.Start()
func Launch() (err error) {
	server.Start()
	defer func () {
		err2 := server.Stop()
		if err == nil {
			err = err2
		}
	}()
	err = Open()
	return err
}
