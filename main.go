package main

import (
	"errors"
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

	// Filters
	app  = fs.String("app", "", "Specify an application (see -list)")
	file = fs.String("file", "", "File to use for operation (restore, whitelist)")

	// Output
	// -count: Just output the count of trusted certs
	format = fs.String("format", "table", "Specify the output format (options: raw, table)")
)

func main() {
	fs.Parse(os.Args[1:])

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
	}

	// Whitelist
	if whitelist != nil && *whitelist {
		if *file == "" {
			exit("", errors.New("no -file specified"))
		}
		err := appChoice(app,
			func(a string) error {
				return cmd.WhitelistForApp(a, *file, *format)
			},
			func() error {
				return cmd.WhitelistForPlatform(*file, *format)
			})
		exit("Whitelist completed successfully", err)
	}

	// List
	if list != nil && *list {
		err := appChoice(app,
			func(a string) error {
				return cmd.ListCertsForApp(*app, *format)
			},
			func() error {
				return cmd.ListCertsForPlatform(*format)
			})
		exit("", err)
	}
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
		fs.PrintDefaults()
		os.Exit(1)
	}
	if msg != "" {
		fmt.Println(msg)
	}
}
