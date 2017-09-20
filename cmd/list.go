package cmd

import (
	"crypto/x509"
	"fmt"
	"github.com/adamdecaf/cert-manage/store"
	"os"
	"strings"
)

// ListCertsForPlatform finds certs for the given platform.
// The supported platforms can be found in the readme. They're compiled in
// with build flags in the `certs/find_*.go` files.
func ListCertsForPlatform(format string) {
	certificates, err := store.Platform().List()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	printCerts(certificates, format)
}

// ListCertsForApp finds certs for the given app.
// The supported applications are listed in the readme. This includes
// non-traditional applications like NSS.
func ListCertsForApp(app string, format string) {
	var certificates []*x509.Certificate
	var err error

	switch strings.ToLower(app) {
	case "chrome":
		certificates, err = store.NssStore().List()
	case "firefox":
		certificates, err = store.NssStore().List()
	case "java":
		certificates, err = store.JavaStore().List()
	default:
		err = fmt.Errorf("application '%s' not found", app)
	}

	// Break if we had some error
	if err != nil {
		fmt.Printf("error finding certificates for application %s\n", err)
		os.Exit(1)
	}

	// Output the certificates
	printCerts(certificates, format)
}
