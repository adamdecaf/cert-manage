package ui

import (
	"crypto/x509"

	"github.com/adamdecaf/cert-manage/ui/server"
)

// TODO(adam): This will need to shake out better
func DefaultFormat() string {
	return "cli"
}
func GetFormats() []string {
	return []string{DefaultFormat(), "web"}
}

// Wrapper on Open() and server.Start()
func Launch() (err error) {
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

// Wrapper on Launch() and server/
func ListCertificates(certs []*x509.Certificate) error {
	server.ListCertificates(certs)
	return Launch()
}
