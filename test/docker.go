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

package test

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/file"
)

var (
	dockerImageMu sync.Mutex
	dockerImages  = map[string]error{}
)

var (
	debug  = os.Getenv("DEBUG") != ""
	mocked = os.Getenv("MOCKED") != ""
)

type dockerfile struct {
	// Local fs path to the Dockerfile
	base string

	// Commands represents a series of commands to be ran in the image
	commands []*Cmd

	// -t flag with build/run
	tag string

	// host path of the generated script, bind-mounted at run
	scriptPath string

	// any errors specific to the dockerfile from `docker` commands
	err error

	// only run build, tag and run steps once
	wg sync.WaitGroup

	// used for cert-manage init
	sync.Once
}

func Dockerfile(where string) *dockerfile {
	if !strings.HasSuffix(where, "Dockerfile") {
		where = filepath.Join(where, "/Dockerfile")
	}

	// Grab the env name (e.g. envs/$env_name/Dockerfile). Stable tags let
	// suite + java tests in the same process share one image build.
	dir := filepath.Dir(where)
	tag := fmt.Sprintf("cert-manage:%s", filepath.Base(dir))

	return &dockerfile{
		base: where,
		tag:  tag,
	}
}

func (d *dockerfile) Run(cmd string, args ...string) {
	d.commands = append(d.commands, Command(cmd, args...))
}

func (d *dockerfile) RunSplit(stmt string) {
	parts := strings.Split(stmt, " ")
	d.Run(parts[0], parts[1:]...)
}

func (d *dockerfile) ShouldFail(cmd string, args ...string) {
	d.Run("set +e")
	d.Run(cmd, args...)
	d.Run("set -e")
}

func (d *dockerfile) ExitCode(code, cmd string, args ...string) {
	d.Run("set +e")
	d.Run(cmd, args...)
	d.Run("code=$?")
	d.Run("set -e")
	d.Run("echo", "$code", "|", "grep", code)
}

// Equals returns an os/exec array of bash commands to check the previous command
func (d *dockerfile) OutputEquals(answer string) []string {
	return []string{
		// store stdout
		">", "/tmp/answer",
		// compare against last line of output
		"&&", fmt.Sprintf(`[ $(tail -1 /tmp/answer) -eq "%s" ]`, answer),
	}
}

func (d *dockerfile) CertManage(args ...string) {
	d.Do(func() {
		d.Run("chmod", "+x", "/bin/cert-manage")
	})
	d.Run("/bin/cert-manage", args...)
}

func (d *dockerfile) CertManageEQ(args, answer string) {
	d.CertManage(append(strings.Split(args, " "), d.OutputEquals(answer)...)...)
}

func linuxBinary() string {
	return filepath.Join("..", "bin", fmt.Sprintf("cert-manage-linux-%s", runtime.GOARCH))
}

func (d *dockerfile) SuccessT(t *testing.T) {
	if !d.enabled() {
		t.Skip("docker isn't enabled")
	}
	if runtime.GOOS != "linux" {
		t.Skip("docker distro tests run on linux")
	}
	if !file.Exists(linuxBinary()) {
		t.Skip("linux binary not built")
	}

	d.prep()
	t.Helper()

	if d.err != nil {
		t.Fatal(d.err)
	}
}

func (d *dockerfile) build() {
	d.wg.Add(1)
	defer d.wg.Done()

	// Copy our original image's contents into the dst file.
	// Image tags contain a colon (cert-manage:alpine); that must not appear
	// in the host path or `docker run -v src:dst` treats the rest as a mode.
	dir, err := ioutil.TempDir("", dockerTempPrefix(d.tag))
	if err != nil {
		d.err = fmt.Errorf("tempfile create err=%v", err)
		return
	}

	copies := []struct{ src, dst string }{
		{"../testdata/Download.java", "Download.java"},
		{"../testdata/globalsign-whitelist.json", "globalsign-whitelist.json"},
		{"../testdata/us-whitelist.yaml", "us-whitelist.yaml"},
		{"../testdata/localcert.pem", "localcert.pem"},
	}
	for i := range copies {
		err = file.CopyFile(copies[i].src, filepath.Join(dir, copies[i].dst))
		if err != nil {
			d.err = fmt.Errorf("error copying %s to tmp dir, err=%v", copies[i].dst, err)
			return
		}
	}

	dst, err := os.Create(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		d.err = fmt.Errorf("tmp Dockerfile create err=%v", err)
		return
	}

	src, err := os.Open(d.base)
	if err != nil {
		d.err = fmt.Errorf("tmpfile open err=%v", err)
		return
	}
	if _, err := io.Copy(dst, src); err != nil {
		d.err = fmt.Errorf("src->dst copy err=%v", err)
		return
	}
	if err := src.Close(); err != nil {
		d.err = fmt.Errorf("src close err=%v", err)
		return
	}
	// Force all writes into our Dockerfile
	if err := dst.Sync(); err != nil {
		d.err = fmt.Errorf("dst fsync err=%v", err)
		return
	}
	if err := dst.Close(); err != nil {
		d.err = fmt.Errorf("dst close err=%v", err)
		return
	}

	// Script is bind-mounted at run so suite and java tests share one image.
	script, err := os.Create(filepath.Join(dir, "script.sh"))
	if err != nil {
		d.err = err
		return
	}
	_, err = script.WriteString(`#!/bin/sh
set +x
set -e` + "\n") // force newline
	if err != nil {
		d.err = err
		return
	}
	for i := range d.commands {
		line := formatScriptLine(d.commands[i]) + "\n"
		if _, err := script.WriteString(line); err != nil {
			d.err = fmt.Errorf("command=%q err=%v", line, err)
			return
		}
	}
	if err := script.Sync(); err != nil {
		d.err = err
		return
	}
	if err := script.Close(); err != nil {
		d.err = err
		return
	}
	if err := os.Chmod(script.Name(), 0755); err != nil {
		d.err = err
		return
	}
	d.scriptPath, err = filepath.Abs(script.Name())
	if err != nil {
		d.err = err
		return
	}

	d.err = ensureDockerImage(d.tag, dir)
}

func (d *dockerfile) run() {
	d.wg.Add(1)
	defer d.wg.Done()

	// don't attempt anything if we've already failed
	if d.err != nil {
		return
	}

	args := []string{"run", "--rm"}
	if debug {
		args = append(args, "-e", "DEBUG=true")
	}
	if d.scriptPath != "" {
		args = append(args, bindMount(d.scriptPath, "/bin/script.sh")...)
	}
	if bin := linuxBinary(); file.Exists(bin) {
		abs, err := filepath.Abs(bin)
		if err != nil {
			d.err = err
			return
		}
		if err := os.Chmod(abs, 0755); err != nil {
			d.err = err
			return
		}
		args = append(args, bindMount(abs, "/bin/cert-manage")...)
	}
	args = append(args, "-t", d.tag)

	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		d.err = fmt.Errorf("ERROR: err=%v\nOutput: %s", err, string(out))
	}
	if debug {
		fmt.Println(string(out))
	}
}

func (d *dockerfile) prep() {
	d.build()
	d.run()
	d.wg.Wait()
}

func (d *dockerfile) enabled() bool {
	return IsDockerEnabled()
}

func IsDockerEnabled() bool {
	if mocked {
		return false
	}

	out, err := exec.Command("docker", "ps").CombinedOutput()
	if err != nil || bytes.Contains(out, []byte("Cannot connect to the Docker daemon")) {
		return false
	}

	// Docker creates '.dockerenv' in the FS root, so if we see that
	// declare docker is disabled (avoid docker-in-docker)
	return !file.Exists("/.dockerenv")
}

func ensureDockerImage(tag, contextDir string) error {
	dockerImageMu.Lock()
	defer dockerImageMu.Unlock()
	if err, ok := dockerImages[tag]; ok {
		return err
	}
	out, err := exec.Command("docker", "build", "-t", tag, contextDir).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("ERROR: err=%v\nOutput: %s", err, string(out))
	}
	dockerImages[tag] = err
	return err
}

// formatScriptLine renders a command into a POSIX shell line. `sh -c` bodies
// are single-quoted so `$()`, pipes, and tests survive as one script.
func formatScriptLine(c *Cmd) string {
	if c == nil {
		return ""
	}
	if c.command == "sh" && len(c.args) >= 2 && c.args[0] == "-c" {
		return "sh -c " + posixQuote(strings.Join(c.args[1:], " "))
	}
	parts := make([]string, 0, 1+len(c.args))
	parts = append(parts, c.command)
	parts = append(parts, c.args...)
	return strings.Join(parts, " ")
}

func posixQuote(s string) string {
	return "'" + strings.Replace(s, "'", `'"'"'`, -1) + "'"
}

func dockerTempPrefix(tag string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ':', '/', '\\':
			return '-'
		default:
			return r
		}
	}, tag)
}

func bindMount(host, dest string) []string {
	return []string{"--mount", fmt.Sprintf("type=bind,source=%s,target=%s", host, dest)}
}
