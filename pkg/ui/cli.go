package ui

import (
	"crypto/x509"
	"fmt"
	"os"
)

// showCertsOnCli outputs the slice of certificates in `cfg.Format` to stdout
func showCertsOnCli(certs []*x509.Certificate, cfg *Config) error {
	p, ok := getPrinter(cfg.Format)
	if !ok {
		return fmt.Errorf("Unknown format %s specified", cfg.Format)
	}
	p.write(os.Stdout, certs)
	return nil
}
