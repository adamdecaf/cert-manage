package cmd

import (
	"fmt"
	"os"

	"github.com/adamdecaf/cert-manage/store"
	"github.com/adamdecaf/cert-manage/ui"
)

// ListCertsForPlatform finds certs for the given platform.
// The supported platforms can be found in the readme. They're compiled in
// with build flags in the `certs/find_*.go` files.
func ListCertsForPlatform(cfg *ui.Config) error {
	certificates, err := store.Platform().List()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if cfg.Count {
		fmt.Println(len(certificates))
	} else {
		ui.ListCertificates(certificates, cfg)
	}
	return nil
}

// ListCertsForApp finds certs for the given app.
// The supported applications are listed in the readme. This includes
// non-traditional applications like NSS.
func ListCertsForApp(app string, cfg *ui.Config) error {
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
	if cfg.Count {
		fmt.Println(len(certificates))
	} else {
		ui.ListCertificates(certificates, cfg)
	}
	return nil
}
