package cmd

import (
	"crypto/x509"
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
	"os"
	"strings"
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

// `FindCertsForApp` finds certs for the given app.
// The supported applications are listed in the readme. This includes
// non-traditional applications like NSS.
func FindCertsForApp(app string, format string) {
	var certificates []*x509.Certificate
	var err error

	switch strings.ToLower(app) {
	case "chrome":
		certificates, err = certs.FindCertsNSS()
	case "java":
		certificates, err = certs.FindCertsJava()
	default:
		err = fmt.Errorf("application '%s' not found", app)
	}

	// Break if we had some error
	if err != nil {
		fmt.Printf("error finding certificates for application %s\n", err)
		os.Exit(1)
	}

	// Output the certificates
	PrintCerts(certificates, format)
}
