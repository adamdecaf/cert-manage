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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/cmd"
	"github.com/adamdecaf/cert-manage/pkg/store"
	"github.com/adamdecaf/cert-manage/pkg/ui"
)

const Version = "0.1.1-dev"

var (
	fs = flag.NewFlagSet("flags", flag.ExitOnError)

	// incantations of "--help"
	flagHelp1 = fs.Bool("h", false, "")
	flagHelp2 = fs.Bool("help", false, "")
	flagHelp3 = fs.Bool("-help", false, "") // --help

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

	// internal override to show help text
	callForHelp = false
)

func init() {
	fs.Usage = func() {
		fmt.Printf(`Usage of cert-manage (version %s)
SUB-COMMANDS
  add           Add certificate(s) to a store
                Accepts: -app, -file

  backup        Take a backup of the specified certificate store

  gen-whitelist Create a whitelist from various sources

  list          List the currently installed and trusted certificates

  restore       Revert the certificate trust back to, optionally takes -file <path>

  version       Show the version of cert-manage

  whitelist     Remove trust from certificates which do not match the whitelist in <path>

APPS
  Supported apps: %s

FLAGS
  -app <name>      The name of an application which to perform the given command on. (Examples: chrome, java)
  -file <path>     Local file path
  -from <type(s)>  Which sources to capture urls from. Comma separated list. (Options: browser, chrome, firefox, file)
  -help            Show this help dialog
  -ui <type>       Method of adjusting certificates to be removed/untrusted. (default: %s, options: %s)
  -url <where>     Remote URL to download and use in a command

OUTPUT
  -count  Output the count of certificates instead of each certificate
  -format <format> Change the output format for a given command (default: %s, options: %s)

DEBUGGING
  Alongside command line flags are two environmental varialbes read by cert-manage:
  - DEBUG=1        Enabled debug logging, GODEBUG=x509roots=1 also works and enabled Go's debugging
  - TRACE=<where>  Saves a binary trace file at <where> of the execution
`,
			getVersion(),
			strings.Join(store.GetApps(), ", "),
			ui.DefaultUI(),
			strings.Join(ui.GetUIs(), ", "),
			ui.DefaultFormat(),
			strings.Join(ui.GetFormats(), ", "),
		)
	}
}

func calledHelp() bool {
	return callForHelp || *flagHelp1 || *flagHelp2 || *flagHelp3
}

type command struct {
	fn    func() error
	appfn func(string) error

	help string
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
		Count:   *flagCount,
		Format:  *flagFormat,
		Outfile: *flagOutFile,
		UI:      *flagUi,
	}

	// Build up sub-commands
	commands := make(map[string]*command, 0)
	commands["add"] = &command{
		fn: func() error {
			if *flagFile == "" {
				callForHelp = true
				return nil
			}
			return cmd.AddCertsFromFile(*flagFile)
		},
		appfn: func(a string) error {
			if *flagFile == "" {
				callForHelp = true
				return nil
			}
			return cmd.AddCertsToAppFromFile(a, *flagFile)
		},
		help: fmt.Sprintf(`Usage: cert-manage add -file <path> [-app <name>]

  Add a certificate to the platform store
    cert-manage add -file <path>

  Add a certificate to an application's store
    cert-manage add -file <path> -app <name>

APPS
  Supported apps: %s`,
			strings.Join(store.GetApps(), ", ")),
	}
	commands["backup"] = &command{
		fn: func() error {
			return cmd.BackupForPlatform()
		},
		appfn: func(a string) error {
			return cmd.BackupForApp(a)
		},
		help: fmt.Sprintf(`Usage: cert-manage backup [-app <name>]

  Backup a certificate store. This can be done for the platform or a given app.

APPS
  Supported apps: %s`,
			strings.Join(store.GetApps(), ", ")),
	}
	commands["gen-whitelist"] = &command{
		fn: func() error {
			if *flagOutFile == "" || (*flagFrom == "" && *flagFile == "") {
				callForHelp = true
				return nil
			}
			return cmd.GenerateWhitelist(*flagOutFile, *flagFrom, *flagFile)
		},
		help: fmt.Sprintf(`Usage: cert-manage gen-whitelist -out <where> [-file <file>] [-from <type>]

  Generate a whitelist and write it to the filesystem. (At wherever -out points to.)

  Also, you can pass -file to read a newline delimited file of URL's.
    cert-manage gen-whitelist -file <path> -out whitelist.json

  Generate a whitelist from browser history
    cert-manage gen-whitelist -from firefox -out whitelist.json

  Generate a whitelist from all browsers on a computer
    cert-manage gen-whitelist -from browsers -out whitelist.json

APPS
  Supported apps: %s`,
			strings.Join(store.GetApps(), ", ")),
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
		help: fmt.Sprintf(`Usage: cert-manage list [options]

  List certificates currently installed on the platform or application.

  List certificates from an application
    cert-mange list -app firefox

  List certificates from a file
    cert-mange list -file <path>

  List certificates from a URL
    cert-manage list -url <endpoint>

FORMATTING

  Change the output format (Default: %s, Options: %s)
    cert-manage list -format openssl

  Only show the count of certificates found
    cert-manage list -count
    cert-manage list -app java -count
    cert-manage list -file <path> -count

  Show the certificates on a local webpage (Default: %s, Options: %s)
    cert-manage list -ui web

APPS
  Supported apps: %s`,
			ui.DefaultFormat(),
			strings.Join(ui.GetFormats(), ", "),
			ui.DefaultUI(),
			strings.Join(ui.GetUIs(), ", "),
			strings.Join(store.GetApps(), ", ")),
	}
	commands["restore"] = &command{
		fn: func() error {
			return cmd.RestoreForPlatform(*flagFile)
		},
		appfn: func(a string) error {
			return cmd.RestoreForApp(a, *flagFile)
		},
		help: fmt.Sprintf(`Usage: cert-manaage restore [-app <name>] [-file <path>]

  Restore certificates from the latest backup
    cert-manage restore

  Restore certificates for the platform from a file
    cert-manage restore -file <path>

  Restore certificates for an application from the latest backup
    cert-manage restore -app java

APPS
  Supported apps: %s`,
			strings.Join(store.GetApps(), ", ")),
	}
	commands["whitelist"] = &command{
		fn: func() error {
			if *flagFile == "" {
				callForHelp = true
				return nil
			}
			return cmd.WhitelistForPlatform(*flagFile)
		},
		appfn: func(a string) error {
			if *flagFile == "" {
				callForHelp = true
				return nil
			}
			return cmd.WhitelistForApp(a, *flagFile)
		},
		help: fmt.Sprintf(`Usage: cert-manage whitelist [-app <name>] -file <path>

  Remove untrusted certificates from a store for the platform
    cert-manage whitelist -file whitelist.json

  Remove untrusted certificates in an app
    cert-manage whitelist -file whitelist.json -app java

APPS
  Supported apps: %s`,
			strings.Join(store.GetApps(), ", ")),
	}
	commands["version"] = &command{
		fn: func() error {
			fmt.Printf("%s\n", getVersion())
			return nil
		},
		appfn: func(_ string) error {
			return nil
		},
		help: getVersion(),
	}

	// Run whatever function we've got here..
	c, ok := commands[strings.ToLower(os.Args[1])]
	if !ok || calledHelp() { // sub-command wasn't found
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

	// some flags can set callForHelp, so let's check again
	if calledHelp() {
		fmt.Println(c.help)
		os.Exit(1)
	}
}

func getVersion() string {
	ver := Version
	if strings.HasSuffix(ver, "-dev") {
		out, err := exec.Command("git", "rev-parse", "HEAD").CombinedOutput()
		if err != nil {
			// Just return version if we can't find git
			if strings.Contains(err.Error(), "executable file not found in") {
				return ver
			}
			panic(err)
		}
		ref := strings.TrimSpace(string(out))
		ver += fmt.Sprintf(" (Revision: %s, Go: %s)", ref[:8], runtime.Version())
	}
	return ver
}
