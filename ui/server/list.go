package server

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"github.com/adamdecaf/cert-manage/tools/_x509"
)

func ListCertificates(certs []*x509.Certificate) {
	Register() // if we haven't already

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for i := range certs {
			line := fmt.Sprintf("Subject: %s\n Serial: %d\n",
				_x509.StringifyPKIXName(certs[i].Subject),
				certs[i].SerialNumber)

			io.WriteString(w, line)
		}
	})
}
