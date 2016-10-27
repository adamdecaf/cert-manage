package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/adamdecaf/cert-manage/certs"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

// `Find` finds certs for the given platform or application
func Find(app *string, format string) {
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

	if format == "table" {
		printCertsInTable(certificates)
	} else {
		// -format raw
		printCertsToStdout(certificates)
	}
}

// IStringSlice is a case-insensitive string sorting implementation
type IStringSlice []string
func (p IStringSlice) Len() int           { return len(p) }
func (p IStringSlice) Less(i, j int) bool { return strings.ToLower(p[i]) < strings.ToLower(p[j]) }
func (p IStringSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// printCertsInTable outputs a nicely formatted table of the certs found. This uses golang's
// native text/tabwriter package to align based on the rows given to it.
func printCertsInTable(certs []*x509.Certificate) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "Subject\tIssuer\tPublic Key Algorithm\tFingerprint\tNot Before\tNot After")
	defer w.Flush()

	rows := make([]string, len(certs))
	for i := range certs {
		ss := sha256.New()
		ss.Write(certs[i].RawSubjectPublicKeyInfo)
		fingerprint := hex.EncodeToString(ss.Sum(nil))

		c1 := certs[i].Subject.CommonName
		c2 := certs[i].Issuer.CommonName
		c3 := stringifyPublicKeyAlgo(certs[i].PublicKeyAlgorithm)
		c4 := fingerprint[:16]

		c5 := certs[i].NotBefore.Format("2006-01-02")
		c6 := certs[i].NotAfter.Format("2006-01-02")

		rows[i] = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s", c1, c2, c3, c4, c5, c6)
	}

	sort.Sort(IStringSlice(rows))
	for i := range rows {
		fmt.Fprintln(w, rows[i])
	}
}

// printCertsToStdout very verbosly prints out the ecah certificate's information
// to stdout. This isn't very useful for machine parsing or small screen displays.
func printCertsToStdout(certs []*x509.Certificate) {
	for i := range certs[:10] {
		ss := sha256.New()
		ss.Write(certs[i].RawSubjectPublicKeyInfo)
		fingerprint := hex.EncodeToString(ss.Sum(nil))

		fmt.Printf("Certificate\n")
		fmt.Printf("  SHA256 Fingerprint - %s\n", fingerprint)
		fmt.Printf("  Signature Algorithm: %s\n", certs[i].SignatureAlgorithm.String())
		fmt.Printf("  Public Key Algorithm - %v\n", stringifyPublicKeyAlgo(certs[i].PublicKeyAlgorithm))
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


func stringifyPublicKeyAlgo(p x509.PublicKeyAlgorithm) string {
	res := "Unknown"
	switch p {
	case x509.RSA:
		res = "RSA"
	case x509.DSA:
		res = "DSA"
	case x509.ECDSA:
		res = "ECDSA"
	}
	return res
}
