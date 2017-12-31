package ui

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"github.com/adamdecaf/cert-manage/tools/_x509"
	"github.com/adamdecaf/cert-manage/ui/server"
)

func launch() (err error) {
	server.Register()
	server.Start()
	defer func() {
		err2 := server.Stop()
		if err == nil {
			err = err2
		}
	}()
	err = Open()
	return err
}

func showCertsOnWeb(certs []*x509.Certificate, cfg *Config) error {
	server.Register()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for i := range certs {
			line := fmt.Sprintf("Subject: %s\n Serial: %d\n",
				_x509.StringifyPKIXName(certs[i].Subject),
				certs[i].SerialNumber)

			io.WriteString(w, line)
		}
	})

	return launch()
}
