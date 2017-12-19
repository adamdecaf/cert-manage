package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/adamdecaf/cert-manage/cmd"
)

const (
	version = "0.0.1-dev"
)

var (
	fs = flag.NewFlagSet("flags", flag.ExitOnError)

	// Qualifiers
	file = fs.String("file", "", "File to use for operation (restore, whitelist)")

	// Filters
	app = fs.String("app", "", "Specify an application (see -list)")

	// Output
	count  = fs.Bool("count", false, "Just output the count of certificates rather than every cert")
	format = fs.String("format", "table", "Specify the output format (options: raw, table)")
)

func init() {
	fs.Usage = func() {
		fmt.Printf(`Usage of cert-manage (version %s)
SUB-COMMANDS
  backup   Take a backup of the specified certificate store
           Accepts: -app

  list     List the currently installed and trusted certificates
           Accepts: -app, -count, -format

  restore  Revert the certificate trust back to, optionally takes -file <path>
           Accepts: -app, -file

  version  Show the version of cert-manage

  whitelist -file <path>   Remove trust from certificates which do not match the whitelist in <path>
                           Accepts: -app, -file

FILTERS
  -app <name> The name of an application which to perform the given command on. (Examples: chrome, java)

OUTPUT
  -count  Output the count of certificates instead of each certificate
  -format <format> Change the output format for a given command (default: table, options: table, raw)
`, version)
	}
}

type command struct {
	fn    func() error
	appfn func(string) error
}

func main() {
	// Just show help if there aren't enough arguments to do anything
	if len(os.Args) < 2 {
		fs.Usage()
		return
	}

	// Lift config options into a higher-level
	fs.Parse(os.Args[2:])
	cfg := &cmd.Config{
		Count:  *count,
		Format: *format,
	}

	// Build up sub-commands
	cmds := make(map[string]*command, 0)
	cmds["backup"] = &command{
		fn: func() error {
			return cmd.BackupForPlatform()
		},
		appfn: func(a string) error {
			return cmd.BackupForApp(a)
		},
	}
	cmds["list"] = &command{
		fn: func() error {
			return cmd.ListCertsForPlatform(cfg)
		},
		appfn: func(a string) error {
			return cmd.ListCertsForApp(a, cfg)
		},
	}
	cmds["restore"] = &command{
		fn: func() error {
			return cmd.RestoreForPlatform(*file)
		},
		appfn: func(a string) error {
			return cmd.RestoreForApp(a, *file)
		},
	}
	cmds["whitelist"] = &command{
		fn: func() error {
			if *file == "" {
				return errors.New("no -file specified")
			}
			return cmd.WhitelistForPlatform(*file)
		},
		appfn: func(a string) error {
			if *file == "" {
				return errors.New("no -file specified")
			}
			return cmd.WhitelistForApp(a, *file)
		},
	}
	cmds["version"] = &command{
		fn: func() error {
			fmt.Printf("%s\n", version)
			return nil
		},
		appfn: func(_ string) error {
			return nil
		},
	}

	// Run whatever function we've got here..
	c, ok := cmds[strings.ToLower(os.Args[1])]
	if !ok { // sub-cmd wasn't found
		fs.Usage()
		os.Exit(1)
	}

	// sub-command found, try and exec something off it
	if app != nil && *app != "" {
		err := c.appfn(*app)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	err := c.fn()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}
}
