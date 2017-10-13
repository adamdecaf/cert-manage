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
	list      = fs.Bool("list", false, "List certificates (by default on the system, see -app)")
	whitelist = fs.String("whitelist", "", "Filter certificates according to the provided whitelist")
	// TODO(adam): future commands
	// - backup
	// - restore

	// Filters
	app = fs.String("app", "", "Specify an application (see -list)")

	// Output
	format = fs.String("format", "table", "Specify the output format (options: raw, table)")
)

func main() {
	fs.Parse(os.Args[1:])

	wh := strings.TrimSpace(*whitelist)
	if whitelist != nil && wh != "" {
		if app != nil && *app != "" {
			err := cmd.WhitelistForApp(*app, *whitelist, *format)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		err := cmd.WhitelistForPlatform(*whitelist, *format)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if list != nil && *list {
		if app != nil && *app != "" {
			cmd.ListCertsForApp(*app, *format)
			return
		}
		cmd.ListCertsForPlatform(*format)
		return
	}
}
