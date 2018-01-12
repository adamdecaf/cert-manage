// +build darwin

package ui

import (
	"fmt"
	"os/exec"

	"github.com/adamdecaf/cert-manage/pkg/ui/server"
)

func Open() error {
	cmd := exec.Command("open", server.Address())
	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("ERROR: while loading ui, err=%v\n", err)
	}
	return err
}
