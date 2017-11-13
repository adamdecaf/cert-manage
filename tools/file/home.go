package file

import (
	"os/user"
)

func HomeDir() string {
	home := homeDir()
	if home != "" {
		return home
	}

	u, err := user.Current()
	if err == nil {
		return u.HomeDir
	}
	return ""
}
