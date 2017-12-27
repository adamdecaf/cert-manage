package cmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/adamdecaf/cert-manage/tools/_x509"
	"github.com/adamdecaf/cert-manage/tools/file"
)

const (
	fingerprintPreviewLength = 16
)

// PrintCerts outputs the slice of certificates in `format` to stdout
// Format can be 'table' and any other value will output them in more detail
func printCerts(certs []*x509.Certificate, format string) {
	if len(certs) == 0 {
		fmt.Println("No certififcates to display")
		os.Exit(1)
	}

	if format == "table" {
		printCertsInTable(certs)
	} else {
		printCertsToStdout(certs)
	}
}

// printCertsInTable outputs a nicely formatted table of the certs found. This uses golang's
// native text/tabwriter package to align based on the rows given to it.
func printCertsInTable(certs []*x509.Certificate) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "Subject\tIssuer\tPublic Key Algorithm\tSHA256 Fingerprint\tNot Before\tNot After")
	defer func() {
		err := w.Flush()
		if err != nil {
			fmt.Printf("error flushing output table - %s\n", err)
		}
	}()

	rows := make([]string, len(certs))
	for i := range certs {
		fingerprint := _x509.GetHexSHA256Fingerprint(*certs[i])

		c1 := fmtPkixName(certs[i].Subject)
		c2 := fmtPkixName(certs[i].Issuer)
		c3 := _x509.StringifyPubKeyAlgo(certs[i].PublicKeyAlgorithm)
		c4 := fingerprint[:fingerprintPreviewLength]

		c5 := certs[i].NotBefore.Format("2006-01-02")
		c6 := certs[i].NotAfter.Format("2006-01-02")

		rows[i] = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s", c1, c2, c3, c4, c5, c6)
	}

	file.SortNames(rows)
	for i := range rows {
		fmt.Fprintln(w, rows[i])
	}
}

// printCertsToStdout very verbosly prints out the ecah certificate's information
// to stdout. This isn't very useful for machine parsing or small screen displays.
func printCertsToStdout(certs []*x509.Certificate) {
	for i := range certs {
		fmt.Printf("Certificate\n")
		fmt.Printf("  SHA1 Fingerprint - %s\n", _x509.GetHexSHA1Fingerprint(*certs[i]))
		fmt.Printf("  SHA256 Fingerprint - %s\n", _x509.GetHexSHA256Fingerprint(*certs[i]))
		fmt.Printf("  SerialNumber: %d\n", certs[i].SerialNumber)
		fmt.Printf("  Subject: %s\n", fmtPkixName(certs[i].Subject))
		fmt.Printf("  Issuer: %s\n", fmtPkixName(certs[i].Issuer))
		fmt.Printf("  NotBefore - %s, NotAfter - %s\n", certs[i].NotBefore, certs[i].NotAfter)
		fmt.Printf("  IsCA - %t\n", certs[i].IsCA)

		if len(certs[i].DNSNames) > 0 {
			fmt.Printf("  DNSNames\n")
			for j := range certs[i].DNSNames {
				fmt.Printf("    %s\n", certs[i].DNSNames[j])
			}
		}

		if len(certs[i].EmailAddresses) > 0 {
			fmt.Printf("  EmailAddresses\n")
			for j := range certs[i].EmailAddresses {
				fmt.Printf("    %s\n", certs[i].EmailAddresses[j])
			}
		}

		if len(certs[i].IPAddresses) > 0 {
			fmt.Printf("  IPAddresses\n")
			for j := range certs[i].IPAddresses {
				fmt.Printf("    %s\n", certs[i].IPAddresses[j])
			}
		}

		if len(certs[i].PermittedDNSDomains) > 0 {
			fmt.Printf("  PermittedDNSDomains\n")
			for j := range certs[i].PermittedDNSDomains {
				fmt.Printf("    %s\n", certs[i].PermittedDNSDomains[j])
			}
		}

		if len(certs[i].CRLDistributionPoints) > 0 {
			fmt.Printf("  CRLDistributionPoints\n")
			for j := range certs[i].CRLDistributionPoints {
				fmt.Printf("    %s\n", certs[i].CRLDistributionPoints[j])
			}
		}
	}
}

func fmtPkixName(name pkix.Name) string {
	if len(name.OrganizationalUnit) > 0 {
		return fmt.Sprintf("%s, %s", strings.Join(name.Organization, " "), name.OrganizationalUnit[0])
	}
	return strings.Join(name.Organization, " ")
}
