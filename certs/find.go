package certs

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// `FindCertsForApplication` is a factory for choosing the proper discovery
// steps for an application's trusted certs.
// On error an empty array will be returned along with a non-nil error value.
func FindCertsForApplication(app string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var err error

	switch strings.ToLower(app) {
	case "chrome":
		certs, err = FindCertsChrome()
	case "java":
		certs, err = FindCertsJava()
	default:
		err = fmt.Errorf("application '%s' not found", app)
	}

	return certs, err
}
