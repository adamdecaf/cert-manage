package cmd

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
	"os"
)

// `FindCertsForPlatform` finds certs for the given platform.
// The supported platforms can be found in the readme. They're compiled in
// with build flags in the `certs/find_*.go` files.
func FindCertsForPlatform(app *string, format string) {
	certificates, err := certs.FindCerts()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	PrintCerts(certificates, format)
}
