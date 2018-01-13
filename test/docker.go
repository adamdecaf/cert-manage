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
	"time"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

var (
	debug = os.Getenv("DEBUG") != ""
)

type dockerfile struct {
	// Local fs path to the Dockerfile
	base string

	// Commands represents a series of commands to be ran in the image
	commands []*Cmd

	// -t flag with build/run
	tag string

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

	// Grab the env name (e.g. envs/$env_name/Dockerfile)
	dir := filepath.Dir(where)
	now := time.Now().Unix()
	tag := fmt.Sprintf("cert-manage:%s-%d", filepath.Base(dir), now)

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

func (d *dockerfile) CertManage(args ...string) {
	d.Do(func() {
		d.Run("chmod", "+x", "/bin/cert-manage")
	})
	d.Run("/bin/cert-manage", args...)
}

func (d *dockerfile) SuccessT(t *testing.T) {
	if runtime.GOOS == "darwin" {
		err := exec.Command("docker", "verison").Run()
		if err == nil {
			t.Fatal("travis-ci supports docker on OSX?? - https://docs.travis-ci.com/user/docker/")
		}
		if inCI() {
			t.Skip("travis-ci doesn't support docker on OSX - https://docs.travis-ci.com/user/docker/")
		}
	}

	if !d.enabled() {
		t.Skip("docker isn't enabled")
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

	// Copy our original image's contents into the dst file
	dir, err := ioutil.TempDir("", d.tag)
	if err != nil {
		d.err = fmt.Errorf("tempfile create err=%v", err)
		return
	}

	// Copy cert-manage and whitelist to the temp directory and assume it's linux
	copyable := []string{
		"../bin/cert-manage-linux-amd64",
		"../testdata/Download.java",
		"../testdata/globalsign-whitelist.json",
	}
	for i := range copyable {
		name := filepath.Base(copyable[i])
		err = file.CopyFile(copyable[i], filepath.Join(dir, name))
		if err != nil {
			d.err = fmt.Errorf("error copying %s to tmp dir, err=%v", name, err)
			return
		}
	}

	dst, err := os.Create(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		d.err = fmt.Errorf("tmp Dockerfile create err=%v", err)
		return
	}
	defer os.Remove(dst.Name())

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

	// Add all commands to a script copied Dockerfile
	script, err := os.Create(filepath.Join(dir, "script.sh"))
	if err != nil {
		d.err = err
		return
	}
	defer os.Remove(script.Name())
	_, err = script.WriteString(`#!/bin/sh` + "\n")
	if err != nil {
		d.err = err
		return
	}
	for i := range d.commands {
		line := fmt.Sprintf("%s %s\n", d.commands[i].command, strings.Join(d.commands[i].args, " "))
		if _, err := script.WriteString(line); err != nil {
			d.err = fmt.Errorf("command=%q err=%v", line, err)
			return
		}
	}
	d.err = script.Sync()
	if d.err != nil {
		return
	}

	// Build docker image now
	out, err := exec.Command("docker", "build", "-t", d.tag, dir).CombinedOutput()
	if err != nil {
		d.err = fmt.Errorf("ERROR: err=%v\nOutput: %s", err, string(out))
	}
}

func (d *dockerfile) run() {
	d.wg.Add(1)
	defer d.wg.Done()

	// don't attempt anything if we've already failed
	if d.err != nil {
		return
	}

	out, err := exec.Command("docker", "run", "-t", d.tag).CombinedOutput()
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
	out, _ := exec.Command("docker", "ps").CombinedOutput()
	if bytes.Contains(out, []byte("Cannot connect to the Docker daemon")) {
		return false
	}
	return true
}
