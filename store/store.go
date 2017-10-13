package store

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/adamdecaf/cert-manage/whitelist"
)

var (
	ErrNoBackupMade = errors.New("unable to make backup of store")
)

// Store represents a certificate store (often called 'pool') and has
// operations on it which mutate the underlying state (e.g. a file or
// directory).
type Store interface {
	// Backup will attempt to save a backup of the certificate store
	// on the local system
	// Backup() error

	// List returns the currently trusted X509 certificates contained
	// within the cert store
	List() ([]*x509.Certificate, error)

	// Remove will distrust the certificate in the store
	//
	// Note: This may not actually delete the certificate, but modify
	// the store such that the certificate is no longer trusted.
	// This is done when possible to limit the actual deletions to
	// preserve restore capabilities
	Remove(whitelist.Whitelist) error
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
