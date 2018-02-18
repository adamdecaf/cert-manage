package test

import (
	"fmt"
	"strings"
	"testing"
)

func TestCertManage_help(t *testing.T) {
	usage := "Usage of cert-manage version"
	subCmdUsage := func(name string) string {
		return fmt.Sprintf("Usage: cert-manage %s ", name)
	}

	// no args, fs.Usage()
	out, err := run(t)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(out, usage) {
		t.Error("expected Usage() text")
	}

	// -h, -help, --help
	choices := []string{"-h", "-help", "--help"}
	for i := range choices {
		out, err = run(t, choices[i])
		if err != nil {
			t.Errorf("choice %q, err=%v", choices[i], err)
		}
		if !strings.Contains(out, usage) {
			t.Errorf("choice %q, expected Usage()", choices[i])
		}
	}

	// sub-command, but no args
	subCommands := []string{"add", "gen-whitelist", "whitelist"}
	for i := range subCommands {
		out, err := run(t, subCommands[i])
		if err != nil && !strings.Contains(err.Error(), "exit status 1") {
			t.Errorf("sub-command %q, err=%v", subCommands[i], err)
		}
		if !strings.Contains(out, subCmdUsage(subCommands[i])) {
			t.Errorf("sub-command %q, expected sub-command usage", subCommands[i])
		}
	}
}

// accepts arguments to cert-manage and then returns the
// stdout/stderr response and error (or nil on success)
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()

	cmd := CertManage(args...)
	return cmd.String(), cmd.Err()
}
