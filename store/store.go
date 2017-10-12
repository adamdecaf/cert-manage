package store

import (
	"crypto/x509"
	"fmt"
	"strings"
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

// ForApp returns a `Store` instance for the given app
func ForApp(app string) (Store, error) {
	switch strings.ToLower(app) {
	case "chrome":
		return NssStore(), nil
	case "firefox":
		return NssStore(), nil
	case "java":
		return JavaStore(), nil
	default:
		return nil, fmt.Errorf("application '%s' not found", app)
	}
}
