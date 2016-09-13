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
		fmt.Printf("  Issuer CommonName - %s, SerialNumber - %s\n", certs[i].Issuer.CommonName, certs[i].Issuer.SerialNumber)
		fmt.Printf("  Subject CommonName - %s, SerialNumber - %s\n", certs[i].Subject.CommonName, certs[i].Subject.SerialNumber)
		fmt.Printf("  NotBefore - %s, NotAfter - %s\n", certs[i].NotBefore, certs[i].NotAfter)
		fmt.Printf("  IsCA - %t\n", certs[i].IsCA)
		fmt.Printf("  MaxPathLen - %d\n", certs[i].MaxPathLen)

		fmt.Printf("  DNSNames\n")
		for j := range certs[i].DNSNames {
			fmt.Printf("    %s\n", certs[i].DNSNames[j])
		}

		fmt.Printf("  EmailAddresses\n")
		for j := range certs[i].EmailAddresses {
			fmt.Printf("    %s\n", certs[i].EmailAddresses[j])
		}

		fmt.Printf("  IPAddresses\n")
		for j := range certs[i].IPAddresses {
			fmt.Printf("    %s\n", certs[i].IPAddresses[j])
		}

		fmt.Printf("  PermittedDNSDomains\n")
		for j := range certs[i].PermittedDNSDomains {
			fmt.Printf("    %s\n", certs[i].PermittedDNSDomains[j])
		}

		fmt.Printf("  CRLDistributionPoints\n")
		for j := range certs[i].CRLDistributionPoints {
			fmt.Printf("    %s\n", certs[i].CRLDistributionPoints[j])
		}
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
