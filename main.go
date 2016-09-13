package main

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
)

func main() {
	certificates, err := certs.FindCerts()
	if err != nil {
		fmt.Println(err)
	}
	certs.PrintCertsToStdout(certificates)
}
