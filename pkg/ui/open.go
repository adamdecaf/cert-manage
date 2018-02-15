// Copyright 2018 Adam Shannon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
