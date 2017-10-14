package main

import (
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

	// Commands
	backup    = fs.Bool("backup", false, "Make a backup")
	list      = fs.Bool("list", false, "List certificates (by default on the system, see -app)")
	whitelist = fs.String("whitelist", "", "Filter certificates according to the provided whitelist")
	// TODO(adam): restore

	// Filters
	app = fs.String("app", "", "Specify an application (see -list)")

	// Output
	// -count: Just output the count of trusted certs
	format = fs.String("format", "table", "Specify the output format (options: raw, table)")
)

func main() {
	fs.Parse(os.Args[1:])

	// Take a backup
	// Note: This always needs to be done first
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
	wh := strings.TrimSpace(*whitelist)
	if whitelist != nil && wh != "" {
		err := appChoice(app,
			func(a string) error {
				return cmd.WhitelistForApp(a, *whitelist, *format)
			},
			func() error {
				return cmd.WhitelistForPlatform(*whitelist, *format)
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
		os.Exit(1)
	}
	if msg != "" {
		fmt.Println(msg)
	}
}
