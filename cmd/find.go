package cmd

import (
	"crypto/x509"
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
	"os"
)

// `Find` finds certs for the given platform or application
func Find(app *string) {
	var certificates []*x509.Certificate

	// Find certs for an app
	if app != nil && *app != "" {
		c, err := certs.FindCertsForApplication(*app)
		if err != nil {
			fmt.Printf("error finding certs for application %s\n", err)
			os.Exit(1)
		}
		certificates = c
	} else {
		// Find certs for a platform
		c, err := certs.FindCerts()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		certificates = c
	}

	printCertsToStdout(certificates)
}
