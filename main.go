package main

import (
	"fmt"
	"flag"
	"github.com/adamdecaf/cert-manage/cmd"
	"strings"
)

var (
	// actions
	find = flag.Bool("find", false, "Find certs for application or platform.")
	whitelist = flag.String("whitelist", "", "Deactivate all certs except for those in the given whitelist")
	version = flag.Bool("version", false, "Output the version number")

	// where?
	app = flag.String("app", "", "Find certs for an application (optional)")
)

const Version = "0.0.1-dev"

func main() {
	flag.Parse()

	if version != nil && *version {
		fmt.Println(Version)
		return
	}

	// determine action
	if find != nil && *find {
		cmd.Find(app)
		return
	}
	if whitelist != nil && *whitelist != "" {
		w := strings.TrimSpace(*whitelist)
		cmd.Whitelist(w, app)
		return
	}

	fmt.Println("Run `cert-manage -h` to get help information")
}
