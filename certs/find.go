package certs

import (
	"crypto/x509"
	"fmt"
	"strings"
)

func FindCertsForApplication(app string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	err := fmt.Errorf("app %s not found", app)

	switch strings.ToLower(app) {
	case "chrome":
		certs, err = FindCertsChrome()
	case "java":
		certs, err = FindCertsJava()
	}

	return certs, err
}
