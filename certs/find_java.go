package certs

import (
	"crypto/x509"
)

// shell out on JAVA_HOME or if `java` is on PATH
// Does this need to be platform specific? Is there a cross-platform way to run java code?

func FindCertsJava() ([]*x509.Certificate, error) {
	return nil, nil
}
