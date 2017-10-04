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

	// Filters
	app = fs.String("app", "", "Specify an application (see -list)")

	// Output
	format = fs.String("format", "table", "Specify the output format")
)

func main() {
	fs.Parse(os.Args[1:])

	if list != nil && *list {
		if app != nil && *app != "" {
			cmd.ListCertsForApp(*app, *format)
			return
		}
		cmd.ListCertsForPlatform(*format)
		return
	}

	wh := strings.TrimSpace(*whitelist)
	if whitelist != nil && wh != "" {
		fmt.Println(wh)
		return
	}
}
