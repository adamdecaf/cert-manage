package main

import (
	"flag"
	"github.com/adamdecaf/cert-manage/cmd"
)

const (
	version = "0.0.1-dev"
)

var (
	// Commands
	list = flag.Bool("list", false, "List certificates (by default on the system, see -app)")
	app  = flag.String("app", "", "Specify an application (see -list)")

	// Output
	format = flag.String("format", "table", "Specify the output format")
)

func main() {
	flag.Parse()

	if list != nil && *list {
		if app != nil && *app != "" {
			cmd.ListCertsForApp(*app, *format)
			return
		}
		cmd.ListCertsForPlatform(*format)
		return
	}
}
