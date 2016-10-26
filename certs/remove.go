package certs

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// `RemoveCerts` is a useful wrapper around the app/platform specific
// removal step(s).
func RemoveCerts(certs []x509.Certificate) []error {
	var errors []error

	for i := range certs {
		err := removeCert(certs[i])
		if err != nil {
			errors = append(errors, *err)
		}
	}

	return errors
}

// `RemoveCertsForApplication` is a factory for choosing the proper removal
// steps for an application.
// On error an empty array will be returned along with a non-nil error value.
func RemoveCertsForApplication(app string, certs []x509.Certificate) []error {
	var errors []error

	switch strings.ToLower(app) {
	case "chrome":
		errors = RemoveCertsChrome(certs)
	case "java":
		errors = RemoveCertsJava(certs)
	default:
		err := fmt.Errorf("application '%s' not found", app)
		errors = append(errors, err)
	}

	return errors
}
