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

	"github.com/adamdecaf/cert-manage/tools/file"
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

	// Copy cert-manage to the temp directory and assume it's linux
	err = file.CopyFile("../bin/cert-manage-linux-amd64", filepath.Join(dir, "cert-manage"))
	if err != nil {
		d.err = fmt.Errorf("error copying cert-manage to tmp dir, err=%v", err)
		return
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

	// Add all commands to the Dockerfile
	initial := "CMD "
	command := initial
	for i := range d.commands {
		if command != initial {
			command += " && "
		}
		command += fmt.Sprintf("%s %s", d.commands[i].command, strings.Join(d.commands[i].args, " "))
	}
	if _, err := dst.WriteString(command); err != nil {
		d.err = fmt.Errorf("command=%s err=%v", command, err)
		return
	}

	// Force all writes into our Dockerfile
	if err := dst.Sync(); err != nil {
		d.err = fmt.Errorf("dst fsync err=%v", err)
		return
	}

	cmd := exec.Command("docker", "build", "-t", d.tag, dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		d.err = fmt.Errorf("ERROR: err=%v\nOutput: %s", err, stderr.String())
	}
}

func (d *dockerfile) run() {
	d.wg.Add(1)
	defer d.wg.Done()

	// don't attempt anything if we've already failed
	if d.err != nil {
		return
	}

	cmd := exec.Command("docker", "run", "-t", d.tag)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		d.err = fmt.Errorf("ERROR: err=%v\nOutput: %s", err, stderr.String())
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
