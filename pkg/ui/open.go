package ui

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/adamdecaf/cert-manage/pkg/ui/server"
)

func Open() error {
	var command string
	switch runtime.GOOS {
	case "darwin":
		command = "open"
	case "linux":
		command = "xdg-open"
	}

	if command != "" {
		cmd := exec.Command(command, server.Address())
		_, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("ERROR: while loading ui, err=%v\n", err)
		}
		return err
	}

	fmt.Printf("WARN: ui not supported on %s yet\n", runtime.GOOS)
	return nil
}
