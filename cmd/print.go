package cmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	"github.com/adamdecaf/cert-manage/tools/_x509"
	"github.com/adamdecaf/cert-manage/tools/file"
	"github.com/adamdecaf/cert-manage/tools/pem"
)

const (
	fingerprintPreviewLength = 16
)

var (
	defaultOutputFormat = "table"

	outputFormats = map[string]func([]*x509.Certificate){
		"openssl":                   printCertsOpenSSL,
		string(defaultOutputFormat): printCertsTable,
		"raw": printCertsRaw,
	}
)

func DefaultOutputFormat() string {
	return defaultOutputFormat
}
func GetOutputFormats() []string {
	out := make([]string, 0)
	for k, _ := range outputFormats {
		out = append(out, k)
	}
	return out
}

// PrintCerts outputs the slice of certificates in `format` to stdout
// Format can be 'table' and any other value will output them in more detail
func printCerts(certs []*x509.Certificate, format string) {
	if len(certs) == 0 {
		fmt.Println("No certififcates to display")
		os.Exit(1)
	}

	fn, ok := outputFormats[strings.ToLower(format)]
	if !ok {
		fmt.Printf("Unknown format %s specified", format)
		return
	}
	fn(certs)
}

// printCertsTable outputs a nicely formatted table of the certs found. This uses golang's
// native text/tabwriter package to align based on the rows given to it.
func printCertsTable(certs []*x509.Certificate) {
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

type openssl struct{}

func (o *openssl) installed() bool {
	err := exec.Command("openssl", "version").Run()
	return err == nil
}
func (o *openssl) printCertificate(path string) error {
	out, err := exec.Command("openssl", "x509", "-in", path, "-noout", "-text").CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// printCertsOpenSSL shells out to openssl (if available) to print out each certificate
func printCertsOpenSSL(certs []*x509.Certificate) {
	ossl := openssl{}

	// fail if we can't find openssl
	if !ossl.installed() {
		fmt.Println("Unable to find openssl")
		return
	}

	tmp, err := ioutil.TempFile("", "cert-mange-print-cert")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer os.Remove(tmp.Name())

	wrapper := make([]*x509.Certificate, 1)
	for i := range certs {
		// render each cert to temp file, then `openssl x509 -in tmp.Name() -outform pem`
		wrapper[0] = certs[i]
		err = pem.ToFile(tmp.Name(), wrapper)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = ossl.printCertificate(tmp.Name())
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	return
}

// printCertsRaw very verbosly prints out the ecah certificate's information
// to stdout. This isn't very useful for machine parsing or small screen displays.
func printCertsRaw(certs []*x509.Certificate) {
	for i := range certs {
		fmt.Printf("Certificate\n")
		fmt.Printf("  SHA1 Fingerprint - %s\n", _x509.GetHexSHA1Fingerprint(*certs[i]))
		fmt.Printf("  SHA256 Fingerprint - %s\n", _x509.GetHexSHA256Fingerprint(*certs[i]))
		fmt.Printf("  Signature - %s\n", hex.EncodeToString(certs[i].Signature))
		fmt.Printf("  Signature Algorithm: %s\n", certs[i].SignatureAlgorithm.String())
		fmt.Printf("  SerialNumber: %d\n", certs[i].SerialNumber)
		fmt.Printf("  Public Key Algorithm - %v\n", _x509.StringifyPubKeyAlgo(certs[i].PublicKeyAlgorithm))
		fmt.Printf("  Subject: %s\n", fmtPkixName(certs[i].Subject))
		fmt.Printf("  Issuer: %s\n", fmtPkixName(certs[i].Issuer))
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

func fmtPkixName(name pkix.Name) string {
	if len(name.OrganizationalUnit) > 0 {
		return fmt.Sprintf("%s, %s", strings.Join(name.Organization, " "), name.OrganizationalUnit[0])
	}
	return strings.Join(name.Organization, " ")
}
