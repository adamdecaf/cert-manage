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
 
// +build darwin linux 
 
package file 
 
import ( 
	"bytes" 
	"fmt" 
	"os" 
	"os/exec" 
	"syscall" 
) 
 
// execCopy checks if we are in need of dropping to an elevated shell in order to 
// perform a file copy. Otherwise, use the default CopyFile methodep 
func execCopy(src, dst string) error { 
	// Only escalate if the dst path exists and is owned by sudo then 
	sdst, err := os.Stat(dst) 
	if err != nil && !os.IsNotExist(err) { 
		return err 
	} 
 
	// From https://groups.google.com/d/msg/golang-nuts/ywS7xQYJkHY/cRUWjhPfZPQJ 
	uid := sdst.Sys().(*syscall.Stat_t).Uid 
	if uid == 0 { // root 
		return execSudoCopy(src, dst) 
	} 
	return CopyFile(src, dst) 
} 
 
// execSudoCopy drops down to a shell in order to attempt a file copy. 
// This function assumes the paths are valid (and checked) by it's caller 
func execSudoCopy(src, dst string) error { 
	var cmd *exec.Cmd 
	if os.Getuid() == 0 { 
		// already root, no need to sudo 
		cmd = exec.Command("cp", src, dst) 
	} else { 
		cmd = exec.Command("sudo", "cp", src, dst) 
	} 
 
	var stderr bytes.Buffer 
	cmd.Stderr = &stderr 
	err := cmd.Run() 
	if err != nil { 
		if stderr.Len() > 0 { 
			return fmt.Errorf("error copying file from %q to %q, err=%v, stderr=%s", src, dst, err, stderr.String()) 
		} 
		return fmt.Errorf("error copying file from %q to %q, err=%v", src, dst, err) 
	} 
	return nil 
} 
