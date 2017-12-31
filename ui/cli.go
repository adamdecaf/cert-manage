package ui

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// showCertsOnCli outputs the slice of certificates in `cfg.Format` to stdout
func showCertsOnCli(certs []*x509.Certificate, cfg *Config) error {
	p, ok := printers[strings.ToLower(cfg.Format)]
	if !ok {
		return fmt.Errorf("Unknown format %s specified", cfg.Format)
	}
	p.write(os.Stdout, certs)
	return nil
}
