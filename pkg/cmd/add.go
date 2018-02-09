package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/store"
)

func AddCertsFromFile(where string) error {
	st := store.Platform()
	return addCerts(st, where)
}

func AddCertsToAppFromFile(app string, where string) error {
	st, err := store.ForApp(app)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return addCerts(st, where)
}

func addCerts(st store.Store, where string) error {
	bs, err := ioutil.ReadFile(where)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return st.Add(certs)
}
