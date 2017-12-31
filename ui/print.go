package ui

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"text/tabwriter"

	"github.com/adamdecaf/cert-manage/tools/_x509"
	"github.com/adamdecaf/cert-manage/tools/file"
	"github.com/adamdecaf/cert-manage/tools/pem"
)

var (
	printers = map[string]printer{
		"openssl":       opensslPrinter{},
		DefaultFormat(): tablePrinter{},
		"raw":           rawPrinter{},
	}

	fingerprintPreviewLength = 16
)

// Formats - how the data is displayed on the UI
func DefaultFormat() string {
	return "table"
}
func GetFormats() []string {
	out := make([]string, 0)
	for k, _ := range printers {
		out = append(out, k)
	}
	return out
}

type printer interface {
	// write will output the certificates to the given writer
	write(*os.File, []*x509.Certificate)
}

// tablePrinter outputs a nicely formatted table of the certs found. This uses golang's
// native text/tabwriter package to align based on the rows given to it.
type tablePrinter struct{}

func (tablePrinter) write(fd *os.File, certs []*x509.Certificate) {
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
		fingerprint := _x509.GetHexSHA256Fingerprint(*certs[i])

		c1 := _x509.StringifyPKIXName(certs[i].Subject)
		c2 := _x509.StringifyPKIXName(certs[i].Issuer)
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

type opensslPrinter struct{}

func (opensslPrinter) printCertificate(w *os.File, path string, cert []*x509.Certificate) error {
	err := pem.ToFile(path, cert)
	if err != nil {
		return err
	}

	out, err := exec.Command("openssl", "x509", "-in", path, "-noout", "-text").CombinedOutput()
	if err != nil {
		return err
	}

	fmt.Fprintln(w, string(out))
	return nil
}

// printCertsOpenSSL shells out to openssl (if available) to print out each certificate
func (p opensslPrinter) write(w *os.File, certs []*x509.Certificate) {
	tmp, err := ioutil.TempFile("", "cert-mange-print-cert")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer os.Remove(tmp.Name())

	for i := range certs {
		err := p.printCertificate(w, tmp.Name(), certs[i:i+1])
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	return
}

// printCertsRaw very verbosly prints out the ecah certificate's information
// to stdout. This isn't very useful for machine parsing or small screen displays.
type rawPrinter struct{}

func (rawPrinter) write(w *os.File, certs []*x509.Certificate) {
	for i := range certs {
		fmt.Fprintf(w, "Certificate\n")
		fmt.Fprintf(w, "  SHA1 Fingerprint - %s\n", _x509.GetHexSHA1Fingerprint(*certs[i]))
		fmt.Fprintf(w, "  SHA256 Fingerprint - %s\n", _x509.GetHexSHA256Fingerprint(*certs[i]))
		fmt.Fprintf(w, "  SerialNumber: %d\n", certs[i].SerialNumber)
		fmt.Fprintf(w, "  Subject: %s\n", _x509.StringifyPKIXName(certs[i].Subject))
		fmt.Fprintf(w, "  Issuer: %s\n", _x509.StringifyPKIXName(certs[i].Issuer))
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
