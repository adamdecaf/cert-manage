package test

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Ideas
// - run command w/ matcher
// - verify arbitrary fs layer
// - debug, replay commands/output on failure

type Cmd struct {
	*Cmd

	// Embed a `Once` so we can call `exec` only once
	sync.Once

	// Represents the arguments to `os/exec.Command`
	command string
	args    []string

	// Holder of output, always converted to a string for
	// easier comparison and print
	output string

	// Holds the error from an execution
	err error
}

func Command(cmd string, args ...string) *Cmd {
	return &Cmd{
		command: cmd,
		args:    args,
	}
}

// Quick wrapper around platform/arch specific call to cert-manage
// which is located at ../bin/cert-manage-GOOS-GOARCH
func CertManage(args ...string) *Cmd {
	render := func(tpl string) string {
		return fmt.Sprintf(tpl, runtime.GOARCH)
	}

	switch runtime.GOOS {
	case "darwin":
		return Command(render("../bin/cert-manage-osx-%s"), args...)
	case "linux":
		return Command(render("../bin/cert-manage-linux-%s"), args...)
	case "windows":
		return Command(render("../bin/cert-manage-%s.exe"), args...)
	}
	return nil
}

func (c *Cmd) exec() {
	c.Do(func() {
		out, err := exec.Command(c.command, c.args...).CombinedOutput()
		c.output = string(out)
		c.err = err
	})
	return
}

func (c *Cmd) Trim() *Cmd {
	c.exec()
	if c.output != "" {
		c.output = strings.TrimSpace(c.output)
	}
	return c
}

// TODO(adam): rename this to something like CmpFnIntT ? maybe.. what does go-cmp have/do?
func (c *Cmd) CmpFnT(t *testing.T, f func(int) bool) {
	t.Helper()
	c.exec()

	n, err := strconv.Atoi(c.output)
	if err != nil {
		t.Errorf("ERROR: converting '%s' to integer failed, err=%v", c.output, err)
	}
	if !f(n) {
		t.Errorf("ERROR: got %d", n)
	}
}

func (c *Cmd) CmpT(t *testing.T, ans int) {
	t.Helper()
	c.CmpFnT(t, func(i int) bool { return i == ans })
}

func (c *Cmd) FailedT(t *testing.T) {
	t.Helper()
	c.exec()

	if c.err == nil {
		t.Errorf("Expected failure, but seeig none.\n Output: %s", c.output)
	}
}

func (c *Cmd) EqualT(t *testing.T, ans string) {
	t.Helper()
	c.exec()
	if c.output != ans {
		t.Errorf("ERROR: Output did not match expected answer!\n Output: %s\n Answer: %s", c.output, ans)
	}
}

func (c *Cmd) String() string {
	c.exec()

	buf := bytes.NewBufferString(fmt.Sprintf("Command:\n  %s %s\nOutput:\n  %s", c.command, strings.Join(c.args, " "), c.output))
	if c.err != nil {
		buf.WriteString(fmt.Sprintf("\nError:\n  %v", c.err))
	}
	return buf.String()
}

func (c *Cmd) SuccessT(t *testing.T) {
	t.Helper()
	c.exec()

	if c.err != nil {
		t.Errorf("Expected no error, got err=%v", c.err)
	}
}
