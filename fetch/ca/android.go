package ca

import (
	"crypto/x509"
)

// Android returns a slice of the certificates trusted by the Android OS
// TODO(adam): include different versions of android
func Android() ([]*x509.Certificate, error) {
	return nil, nil
}
