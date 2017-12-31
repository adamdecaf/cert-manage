package server

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func ListCertificates(certs []*x509.Certificate) {
	Register() // if we haven't already

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for i := range certs {
			line := fmt.Sprintf("Subject: %s\n Serial: %d\n",
				fmtPkixName(certs[i].Subject),
				certs[i].SerialNumber)

			io.WriteString(w, line)
		}
	})
}

// TODO(adam): from ui/cli.go, replace with RDSSequence.Name() in go1.10 ?
func fmtPkixName(name pkix.Name) string {
	if len(name.OrganizationalUnit) > 0 {
		return fmt.Sprintf("%s, %s", strings.Join(name.Organization, " "), name.OrganizationalUnit[0])
	}
	return strings.Join(name.Organization, " ")
}
