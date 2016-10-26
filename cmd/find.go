package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
	"os"
)

// `Find` finds certs for the given platform or application
func Find(app *string) {
	var certificates []*x509.Certificate

	// Find certs for an app
	if app != nil && *app != "" {
		c, err := certs.FindCertsForApplication(*app)
		if err != nil {
			fmt.Printf("error finding certs for application %s\n", err)
			os.Exit(1)
		}
		certificates = c
	} else {
		// Find certs for a platform
		c, err := certs.FindCerts()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		certificates = c
	}

	printCertsToStdout(certificates)
}

// printCertsToStdout very verbosly prints out the ecah certificate's information
// to stdout. This isn't very useful for machine parsing or small screen displays.
func printCertsToStdout(certs []*x509.Certificate) {
	for i := range certs[:1] {
		fmt.Printf("cert\n")

		ss := sha256.New()
		ss.Write(certs[i].RawSubjectPublicKeyInfo)
		fingerprint := hex.EncodeToString(ss.Sum(nil))

		fmt.Printf("  sha256 fingerprint - %s\n", fingerprint)
		fmt.Printf("  signature algorithm: %s\n", certs[i].SignatureAlgorithm.String())
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
}
