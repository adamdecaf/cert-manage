package main

import (
	"fmt"
	"flag"
	"github.com/adamdecaf/cert-manage/cmd"
)

var (
	// actions
	find = flag.Bool("find", false, "Find certs for application or platform.")
	whitelist = flag.String("whitelist", "", "Deactivate all certs except for those in the given whitelist")

	// where?
	app = flag.String("app", "", "Find certs for an application (optional)")
)

func main() {
	flag.Parse()

	// determine action
	if find != nil && *find {
		cmd.Find(app)
		return
	}
	if whitelist != nil && *whitelist != "" {
		cmd.Whitelist(*whitelist, app)
		return
	}

	fmt.Println("Run `cert-manage -h` to get help information")
}
