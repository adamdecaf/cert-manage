package osx

import (
	"crypto/x509"
	"fmt"
	"encoding/hex"
	"github.com/adamdecaf/cert-manage/lib"
	"os/exec"
)

func findCerts() []*x509.Certificate {
	certs, err := getPEMCertBodiesFromCLI()
	if err != nil {
		return nil
	}

	for i := range certs {
		fmt.Printf("cert\n")
		fmt.Printf("  signature - %s (%s)\n", hex.EncodeToString(certs[i].Signature), certs[i].SignatureAlgorithm.String())
		fmt.Printf("  pub key algo - %d\n", certs[i].PublicKeyAlgorithm)

		// Issuer              pkix.Name
		// Subject             pkix.Name
		// NotBefore, NotAfter time.Time // Validity bounds.

		// IsCA
		// MaxPathLen

		// DNSNames
		// EmailAddresses
		// IPAddresses

		// PermittedDNSDomains

		// CRLDistributionPoints
	}

	return certs
}

func getPEMCertBodiesFromCLI() ([]*x509.Certificate, error) {
	b, err := exec.Command("security", "find-certificate", "-a", "-p").Output()
	if err != nil {
		return nil, err
	}

	certs, err := lib.ParsePEMIntoCerts(b)
	if err != nil {
		return nil, err
	}
	return certs, nil
}
