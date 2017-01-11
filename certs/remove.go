package certs

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// RemoveCerts collects errors from removing certs against a platform.
func RemoveCerts(certs []*x509.Certificate) []error {
	var errors []error

	for i := range certs {
		if certs[i] == nil {
			continue
		}
		err := removeCert(*certs[i])
		if err != nil {
			errors = append(errors, *err)
		}
	}

	return errors
}

// RemoveCertsForApplication accumulates errors when removing certs from an application's store.
func RemoveCertsForApplication(app string, certs []x509.Certificate) []error {
	var errors []error

	switch strings.ToLower(app) {
	case "chrome":
		errors = RemoveCertsNSS(certs)
	case "java":
		errors = RemoveCertsJava(certs)
	default:
		err := fmt.Errorf("application '%s' not found", app)
		errors = append(errors, err)
	}

	return errors
}
