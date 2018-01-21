package ui

import (
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/pem"
)

var (
	defaultFormat = "short"
	printers      = map[string]printer{
		"openssl":     opensslPrinter{},
		"table":       tablePrinter{},
		defaultFormat: shortPrinter{},
	}

	fingerprintPreviewLength = 16
)

// Formats - how the data is displayed on the UI
func DefaultFormat() string {
	return defaultFormat
}
func GetFormats() []string {
	out := make([]string, 0)
	for k := range printers {
		out = append(out, k)
	}
	return out
}

type printer interface {
	close()
	write(io.Writer, []*x509.Certificate)
}

func getPrinter(name string) (printer, bool) {
	p, ok := printers[strings.ToLower(name)]
	return p, ok
}

// tablePrinter outputs a nicely formatted table of the certs found. This uses golang's
// native text/tabwriter package to align based on the rows given to it.
type tablePrinter struct{}

func (tablePrinter) close() {}
func (tablePrinter) write(fd io.Writer, certs []*x509.Certificate) {
	w := tabwriter.NewWriter(fd, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "Subject\tIssuer\tPublic Key Algorithm\tSHA256 Fingerprint\tNot Before\tNot After")
	defer func() {
		err := w.Flush()
		if err != nil {
			fmt.Printf("error flushing output table - %s\n", err)
		}
	}()

	rows := make([]string, len(certs))
	for i := range certs {
		fingerprint := certutil.GetHexSHA256Fingerprint(*certs[i])

		c1 := certutil.StringifyPKIXName(certs[i].Subject)
		c2 := certutil.StringifyPKIXName(certs[i].Issuer)
		c3 := certutil.StringifyPubKeyAlgo(certs[i].PublicKeyAlgorithm)
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

type opensslPrinter struct {
	tmp *os.File
}

func (p opensslPrinter) printCertificate(w io.Writer, cert []*x509.Certificate) error {
	err := pem.ToFile(p.tmp.Name(), cert)
	if err != nil {
		return err
	}

	out, err := exec.Command("openssl", "x509", "-in", p.tmp.Name(), "-noout", "-text").CombinedOutput()
	if err != nil {
		return err
	}

	fmt.Fprintln(w, string(out))
	return nil
}

// printCertsOpenSSL shells out to openssl (if available) to print out each certificate
func (p opensslPrinter) write(w io.Writer, certs []*x509.Certificate) {
	if p.tmp == nil {
		tmp, err := ioutil.TempFile("", "cert-mange-print-cert")
		if err != nil {
			fmt.Println(err)
			return
		}
		p.tmp = tmp
	}

	for i := range certs {
		err := p.printCertificate(w, certs[i:i+1])
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	return
}

func (p opensslPrinter) close() {
	if p.tmp != nil {
		os.Remove(p.tmp.Name())
	}
}

// printCertsRaw very verbosly prints out the ecah certificate's information
// to stdout. This isn't very useful for machine parsing or small screen displays.
type shortPrinter struct{}

func (shortPrinter) close() {}
func (shortPrinter) write(w io.Writer, certs []*x509.Certificate) {
	for i := range certs {
		fmt.Fprintf(w, "Certificate\n")
		fmt.Fprintf(w, "  SHA1 Fingerprint - %s\n", certutil.GetHexSHA1Fingerprint(*certs[i]))
		fmt.Fprintf(w, "  SHA256 Fingerprint - %s\n", certutil.GetHexSHA256Fingerprint(*certs[i]))
		fmt.Fprintf(w, "  SerialNumber: %d\n", certs[i].SerialNumber)
		fmt.Fprintf(w, "  Subject: %s\n", certutil.StringifyPKIXName(certs[i].Subject))
		fmt.Fprintf(w, "  Issuer: %s\n", certutil.StringifyPKIXName(certs[i].Issuer))
		fmt.Fprintf(w, "  NotBefore - %s, NotAfter - %s\n", certs[i].NotBefore, certs[i].NotAfter)
		fmt.Fprintf(w, "  IsCA - %t\n", certs[i].IsCA)

		if len(certs[i].DNSNames) > 0 {
			fmt.Fprintf(w, "  DNSNames\n")
			for j := range certs[i].DNSNames {
				fmt.Fprintf(w, "    %s\n", certs[i].DNSNames[j])
			}
		}

		if len(certs[i].EmailAddresses) > 0 {
			fmt.Fprintf(w, "  EmailAddresses\n")
			for j := range certs[i].EmailAddresses {
				fmt.Fprintf(w, "    %s\n", certs[i].EmailAddresses[j])
			}
		}

		if len(certs[i].IPAddresses) > 0 {
			fmt.Fprintf(w, "  IPAddresses\n")
			for j := range certs[i].IPAddresses {
				fmt.Fprintf(w, "    %s\n", certs[i].IPAddresses[j])
			}
		}

		if len(certs[i].PermittedDNSDomains) > 0 {
			fmt.Fprintf(w, "  PermittedDNSDomains\n")
			for j := range certs[i].PermittedDNSDomains {
				fmt.Fprintf(w, "    %s\n", certs[i].PermittedDNSDomains[j])
			}
		}

		if len(certs[i].CRLDistributionPoints) > 0 {
			fmt.Fprintf(w, "  CRLDistributionPoints\n")
			for j := range certs[i].CRLDistributionPoints {
				fmt.Fprintf(w, "    %s\n", certs[i].CRLDistributionPoints[j])
			}
		}
	}
}
