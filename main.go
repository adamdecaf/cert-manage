package main

import (
	"crypto/x509"
	"fmt"
	"flag"
	"github.com/adamdecaf/cert-manage/certs"
	"os"
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
		findCmd(app)
		return
	}
	if whitelist != nil && *whitelist != "" {
		whitelistCmd(*whitelist, app)
		return
	}

	fmt.Println("Run `cert-manage -h` to get help information")
}

// `fatal` Prints out what we can from the underlying error
// and quits the tool with a non-zero status code.
func fatal(err error) {
	fmt.Printf("ERROR: %s\n", err)
	os.Exit(1)
}

// `find` finds certs for the given platform or application
func findCmd(app *string) {
	var certificates []*x509.Certificate

	// Find certs for an app
	if app != nil && *app != "" {
		c, err := certs.FindCertsForApplication(*app)
		if err != nil {
			fatal(err)
		}
		certificates = c
	}

	// Find certs for a platform
	c, err := certs.FindCerts()
	if err != nil {
		fmt.Println(err)
	}
	certificates = c

	certs.PrintCertsToStdout(certificates)
}

// `whitelistCmd` deactivates all certs except for those in the given
// whitelist.
func whitelistCmd(path string, app *string) {
	return
}
