package ui

import (
	"crypto/x509"

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
	server.ListCertificates(certs)
	return launch()
}
