package main

import (
	"flag"
	"fmt"
	"github.com/adamdecaf/cert-manage/cmd"
	"os"
)

var (
	// Finding application/system certs
	find = flag.Bool("find", false, "Find certs for application or platform.")
	format = flag.String("format", "table", "The output format for certs. options: table, raw")

	// Pruning the trusted certs
	whitelist = flag.String("whitelist", "", "Deactivate all certs except for those in the given whitelist")

	// -app is used by both -find and -whitelist
	app = flag.String("app", "", "Find certs for an application (optional)")

	// Just output the version and exit cleanly
	version = flag.Bool("version", false, "Output the version number")
)

const Version = "0.0.1-dev"

func main() {
	flag.Parse()

	if version != nil && *version {
		fmt.Println(Version)
		return
	}

	if find != nil && *find {
		cmd.Find(app, *format)
		return
	}

	if whitelist != nil && *whitelist != "" {
		err := cmd.Whitelist(*whitelist, app)
		if err != nil {
			os.Exit(1)
		}
		return
	}

	fmt.Println("Run `cert-manage -h` to get help information")
	os.Exit(0)
}
