package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/store"
	"github.com/adamdecaf/cert-manage/pkg/ui"
)

// ListCertsFromFile finds certificates at the given filepath
// and lists them according to the ui/format options.
func ListCertsFromFile(where string, cfg *ui.Config) error {
	bs, err := ioutil.ReadFile(where)
	if err != nil {
		return err
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return ui.ListCertificates(certs, cfg)
}

// ListCertsForPlatform finds certs for the given platform.
// The supported platforms can be found in the readme. They're compiled in
// with build flags in the `certs/find_*.go` files.
func ListCertsForPlatform(cfg *ui.Config) error {
	certificates, err := store.Platform().List()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return ui.ListCertificates(certificates, cfg)
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
	return ui.ListCertificates(certificates, cfg)
}
