package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/adamdecaf/cert-manage/cmd"
)

const (
	version = "0.0.1-dev"
)

var (
	fs = flag.NewFlagSet("flags", flag.ExitOnError)

	// Commands
	backup    = fs.Bool("backup", false, "Make a backup")
	list      = fs.Bool("list", false, "List certificates (by default on the system, see -app)")
	restore   = fs.Bool("restore", false, "Restore from a given backup file, if it exists (and supported)")
	whitelist = fs.Bool("whitelist", false, "Filter certificates according to the provided whitelist")
	ver       = fs.Bool("version", false, "Show the version of cert-manage")

	// Qualifiers
	file = fs.String("file", "", "File to use for operation (restore, whitelist)")

	// Filters
	app = fs.String("app", "", "Specify an application (see -list)")

	// Output
	count  = fs.Bool("count", false, "Just output the count of certificates rather than every cert")
	format = fs.String("format", "table", "Specify the output format (options: raw, table)")
	dryrun = fs.Bool("dry-run", false, "Don't actually delete/untrust certificates, but show a diff instead")
)

func init() {
	fs.Usage = func() {
		fmt.Printf(`Usage of cert-manage (version %s)
COMMANDS
  -backup   Take a backup of the specified certificate store
  -list     List the currently installed and trusted certificates
  -restore  Revert the certificate trust back to, optionally takes -file <path>
  -version  Show the version of cert-manage

  Commands which require a file (via -file)
  -whitelist -file <path> Remove trust from certificates which do not match the whitelist in <path>

FILTERS
  Filters can be applied to the following commands: -backup, -list, -restore, -whitelist
  -app <name> The name of an application which to perform the given command on. (Examples: chrome, java)

OUTPUT
  -format Change the output format for a given command (default: table, options: table, raw)
`, version)
	}
}

func main() {
	fs.Parse(os.Args[1:])

	// Show the version
	if ver != nil && *ver {
		fmt.Printf("%s\n", version)
		return
	}

	// Lift config options into a higher-level
	cfg := &cmd.Config{
		Count:  *count,
		Format: *format,
		DryRun: *dryrun,
	}

	// Perform a restore
	// Note: This always needs to happen before -whitelist and before -backup
	if restore != nil && *restore {
		err := appChoice(app,
			func(a string) error {
				return cmd.RestoreForApp(a, *file)
			},
			func() error {
				return cmd.RestoreForPlatform(*file)
			})
		exit("Restore completed successfully", err)
		return
	}

	// Take a backup
	// Note: This always needs to be done before -whitelist
	if backup != nil && *backup {
		err := appChoice(app,
			func(a string) error {
				return cmd.BackupForApp(a)
			},
			func() error {
				return cmd.BackupForPlatform()
			})
		exit("Backup completed successfully", err)
		return
	}

	// Whitelist
	if whitelist != nil && *whitelist {
		if *file == "" {
			fmt.Println("no -file specified")
			fs.Usage()
			return
		}
		err := appChoice(app,
			func(a string) error {
				return cmd.WhitelistForApp(a, *file, cfg)
			},
			func() error {
				return cmd.WhitelistForPlatform(*file, cfg)
			})
		exit("Whitelist completed successfully", err)
		return
	}

	// List
	if list != nil && *list {
		err := appChoice(app,
			func(a string) error {
				return cmd.ListCertsForApp(*app, cfg)
			},
			func() error {
				return cmd.ListCertsForPlatform(cfg)
			})
		exit("", err)
		return
	}

	// Print usage if no command was ran
	fs.Usage()
}

type fn func() error
type appfn func(string) error

// appChoice decides between `appfn` and `fn` given the presence of `app`
// being non-nil and a non-empty string.
func appChoice(app *string, appfn appfn, fn fn) error {
	if app != nil && *app != "" {
		return appfn(*app)
	}
	return fn()
}

func exit(msg string, err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if msg != "" {
		fmt.Println(msg)
	}
}
