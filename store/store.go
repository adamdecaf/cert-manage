package store

import (
	"crypto/x509"
)

// Store represents a certificate store (often called 'pool') and has
// operations on it which mutate the underlying state (e.g. a file or
// directory).
type Store interface {
	// List returns the currently trusted X509 certificates contained
	// within the cert store
	List() ([]*x509.Certificate, error)
}

// Platform returns a new instance of Store for the running os/platform
func Platform() Store {
	return platform()
}
