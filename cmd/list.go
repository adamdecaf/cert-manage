package cmd

import (
	"fmt"
	"os"

	"github.com/adamdecaf/cert-manage/store"
)

// ListCertsForPlatform finds certs for the given platform.
// The supported platforms can be found in the readme. They're compiled in
// with build flags in the `certs/find_*.go` files.
func ListCertsForPlatform(format string) error {
	certificates, err := store.Platform().List()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	printCerts(certificates, format)
	return nil
}

// ListCertsForApp finds certs for the given app.
// The supported applications are listed in the readme. This includes
// non-traditional applications like NSS.
func ListCertsForApp(app string, format string) error {
	st, err := store.ForApp(app)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	certificates, err := st.List()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Break if we had some error
	if err != nil {
		fmt.Printf("error finding certificates for application %s\n", err)
		os.Exit(1)
	}

	// Output the certificates
	printCerts(certificates, format)
	return nil
}
