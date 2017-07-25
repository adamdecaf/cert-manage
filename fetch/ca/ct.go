package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"github.com/adamdecaf/cert-manage/tools"
)

// TODO(adam): Specify the exact cert used for each CT log
// TODO(adam): When running through, ignore conns that fail?
// TODO(adam): Flag to specify which log(s) to pull from, rather than all?
// TODO(adam): filtering of which CT log servers to pull from
// TODO(adam): pin CT server certs for retrieval

var (
	// The following CT servers was pulled from
	// https://www.certificate-transparency.org/known-logs
	// https://www.gstatic.com/ct/log_list/all_logs_list.json
	ctUrls = []string{
		// "https://alpha.ctlogs.org",
		// "https://clicky.ct.letsencrypt.org",
		// "https://ct.akamai.com",
		// "https://ct.filippo.io/behindthesofa",
		// "https://ct.gdca.com.cn",
		// "https://ct.googleapis.com/aviator",
		"https://ct.googleapis.com/daedalus",
		// "https://ct.googleapis.com/icarus",
		// "https://ct.googleapis.com/pilot",
		// "https://ct.googleapis.com/rocketeer",
		// "https://ct.googleapis.com/skydiver",
		// "https://ct.googleapis.com/submariner",
		// "https://ct.googleapis.com/testtube",
		// "https://ct.izenpe.com",
		// "https://ct.izenpe.eus",
		// "https://ct.sheca.com",
		// "https://ct.startssl.com",
		// "https://ct.wosign.com",
		// "https://ct.ws.symantec.com",
		// "https://ct1.digicert-ct.com/log",
		// "https://ct2.digicert-ct.com/log",
		// "https://ctlog-gen2.api.venafi.com",
		// "https://ctlog.api.venafi.com",
		// "https://ctlog.gdca.com.cn",
		// "https://ctlog.sheca.com",
		// "https://ctlog.wosign.com",
		// "https://ctlog2.wosign.com",
		// "https://ctserver.cnnic.cn",
		// "https://ctserver.cnnic.cn",
		// "https://deneb.ws.symantec.com",
		// "https://dodo.ct.comodo.com",
		// "https://flimsy.ct.nordu.net:8080",
		// "https://log.certly.io",
		// "https://mammoth.ct.comodo.com",
		// "https://plausible.ct.nordu.net",
		// "https://sabre.ct.comodo.com",
		// "https://sirius.ws.symantec.com",
		// "https://vega.ws.symantec.com",
		// "https://www.certificatetransparency.cn/ct",
	}
)

type ctJSON struct {
	Certificates []string `json:"certificates"`
}


func getCTCerts() ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0)

	for i := range ctUrls {
		u := ctUrls[i] + "/ct/v1/get-roots"
		resp, err := http.DefaultClient.Get(u)
		if err != nil {
			return nil, err
		}
		defer func() {
			e := resp.Body.Close()
			if e != nil {
				fmt.Printf("error closing http req to ct server - %s\n", e)
			}
		}()
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		// Decode from json
		var certs ctJSON
		err = json.Unmarshal(b, &certs)
		if err != nil {
			return nil, err
		}

		prefix := []byte("-----BEGIN CERTIFICATE-----\n")
		suffix := []byte("-----END CERTIFICATE-----")
		buf := new(bytes.Buffer)

		for j := range certs.Certificates {
			cert := certs.Certificates[j]

			buf.Write(prefix)
			for k := 0; k < len(cert)/64; k++ {
				buf.WriteString(cert[k*64 : (k+1)*64])
				buf.WriteRune('\n')
			}
			last := cert[(len(cert)/64)*64:]
			if last != "" {
				buf.WriteString(last)
				buf.WriteRune('\n')
			}
			buf.Write(suffix)
			if j != len(certs.Certificates)-1 {
				buf.WriteRune('\n')
			}
		}

		// Only search for certs if we've prepped the buffer
		if buf.Len() > 0 {
			cs, err := tools.ParsePEMIntoCerts(buf.Bytes())
			if err != nil {
				return nil, err
			}

			// Add cert(s) to collection pool
			// TODO(adam): Only uniq insertions, tree/heap structure would be better
			out = append(out, cs...)
		}
	}

	return out, nil
}

// CT returns a slice of the roots from a set of
// certificate transparency servers
func CT() ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0)

	add := func(cs []*x509.Certificate, err error) error {
		if err != nil {
			return err
		}
		out = append(out, cs...)
		return nil
	}

	err := add(getCTCerts())
	if err != nil {
		return nil, err
	}

	return out, nil
}
