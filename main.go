package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/cmd"
	"github.com/adamdecaf/cert-manage/pkg/ui"
)

const Version = "0.0.1-dev"

var (
	fs = flag.NewFlagSet("flags", flag.ExitOnError)

	// -file is used to specify an input file path
	flagFile = fs.String("file", "", "")

	// -url is used to specify an input URL
	flagURL = fs.String("url", "", "")

	// -app is used for operating on an installed application
	flagApp = fs.String("app", "", "")

	// -ui is used for choosing a different ui
	flagUi = fs.String("ui", ui.DefaultUI(), "")

	// -from is used by 'gen-whitelist' to specify url sources
	flagFrom = fs.String("from", "", "")

	// -out is used by 'gen-whitelist' to specify output file location
	flagOutFile = fs.String("out", "", "")

	// Output
	flagCount  = fs.Bool("count", false, "")
	flagFormat = fs.String("format", ui.DefaultFormat(), "")
)

func init() {
	fs.Usage = func() {
		fmt.Printf(`Usage of cert-manage (version %s)
SUB-COMMANDS
  backup        Take a backup of the specified certificate store
                Accepts: -app

  gen-whitelist Create a whitelist from various sources
                Requires: -out, Optional: -file, -from

  list          List the currently installed and trusted certificates
                Accepts: -app, -count, -file, -format, -url

  restore       Revert the certificate trust back to, optionally takes -file <path>
                Accepts: -app, -file

  version       Show the version of cert-manage

  whitelist     Remove trust from certificates which do not match the whitelist in <path>
                Requires: -file, Optional: -app

FLAGS
  -app <name>      The name of an application which to perform the given command on. (Examples: chrome, java)
  -file <path>     Local file path
  -from <type(s)>  Which sources to capture urls from. Comma separated list. (Options: browser, chrome, firefox, file)
  -ui <type>       Method of adjusting certificates to be removed/untrusted. (default: %s, options: %s)
  -url <where>     Remote URL to download and use in a command

OUTPUT
  -count  Output the count of certificates instead of each certificate
  -format <format> Change the output format for a given command (default: %s, options: %s)

DEBUG and TRACE
  Alongside command line flags are two environmental varialbes read by cert-manage:
  - DEBUG=1        Enabled debug logging, GODEBUG=x509roots=1 also works and enabled Go's debugging
  - TRACE=<where>  Saves a binary trace file at <where> of the execution
`,
			Version,
			ui.DefaultUI(),
			strings.Join(ui.GetUIs(), ", "),
			ui.DefaultFormat(),
			strings.Join(ui.GetFormats(), ", "),
		)
	}
}

type command struct {
	fn    func() error
	appfn func(string) error
}

func trace() *cmd.Trace {
	trace, err := cmd.NewTrace(os.Getenv("TRACE"))
	if err != nil {
		panic(err)
	}
	err = trace.Start()
	if err != nil {
		panic(err)
	}
	return trace
}

func main() {
	t := trace()
	defer func() {
		err := t.Stop()
		if err != nil {
			panic(err)
		}
	}()

	// Just show help if there aren't enough arguments to do anything
	if len(os.Args) < 2 {
		fs.Usage()
		return
	}

	// Lift config options into a higher-level
	fs.Parse(os.Args[2:])
	cfg := &ui.Config{
		Count:  *flagCount,
		Format: *flagFormat,
		UI:     *flagUi,
	}

	// Build up sub-commands
	commands := make(map[string]*command, 0)
	commands["backup"] = &command{
		fn: func() error {
			return cmd.BackupForPlatform()
		},
		appfn: func(a string) error {
			return cmd.BackupForApp(a)
		},
	}
	commands["gen-whitelist"] = &command{
		fn: func() error {
			return cmd.GenerateWhitelist(*flagOutFile, *flagFrom, *flagFile)
		},
	}
	commands["list"] = &command{
		fn: func() error {
			if *flagFile != "" {
				return cmd.ListCertsFromFile(*flagFile, cfg)
			}
			if *flagURL != "" {
				return cmd.ListCertsFromURL(*flagURL, cfg)
			}
			return cmd.ListCertsForPlatform(cfg)
		},
		appfn: func(a string) error {
			return cmd.ListCertsForApp(a, cfg)
		},
	}
	commands["restore"] = &command{
		fn: func() error {
			return cmd.RestoreForPlatform(*flagFile)
		},
		appfn: func(a string) error {
			return cmd.RestoreForApp(a, *flagFile)
		},
	}
	commands["whitelist"] = &command{
		fn: func() error {
			if *flagFile == "" {
				return errors.New("no -file specified")
			}
			return cmd.WhitelistForPlatform(*flagFile)
		},
		appfn: func(a string) error {
			if *flagFile == "" {
				return errors.New("no -file specified")
			}
			return cmd.WhitelistForApp(a, *flagFile)
		},
	}
	commands["version"] = &command{
		fn: func() error {
			fmt.Printf("%s\n", Version)
			return nil
		},
		appfn: func(_ string) error {
			return nil
		},
	}

	// Run whatever function we've got here..
	c, ok := commands[strings.ToLower(os.Args[1])]
	if !ok { // sub-command wasn't found
		fs.Usage()
		os.Exit(1)
	}

	// sub-command found, try and exec something off it
	if flagApp != nil && *flagApp != "" {
		err := c.appfn(*flagApp)
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
