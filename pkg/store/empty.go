package store

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

// emptyStore represents a Store which has no implementation
// This is useful for stubs
type emptyStore struct{}

func (s emptyStore) printNotce() {
	fmt.Fprintln(os.Stderr, "NOTICE: This implementation is currently stubbed, nothing is happening.")
}

func (s emptyStore) Backup() error {
	s.printNotce()
	return nil
}
func (s emptyStore) List() ([]*x509.Certificate, error) {
	s.printNotce()
	return nil, nil
}
func (s emptyStore) Remove(whitelist.Whitelist) error {
	s.printNotce()
	return nil
}
func (s emptyStore) Restore(where string) error {
	s.printNotce()
	return nil
}
