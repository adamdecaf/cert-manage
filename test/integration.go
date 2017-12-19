package test

import (
	"bytes"
	"fmt"
	"os/exec"
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

func (c *Cmd) EqualT(t *testing.T, ans string) {
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
