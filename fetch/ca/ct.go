package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"github.com/adamdecaf/cert-manage/tools"
)

var (
	// Google URLs
	googleCTUrls = []string{
		"https://ct.googleapis.com/aviator/ct/v1/get-roots",
		"https://ct.googleapis.com/pilot/ct/v1/get-roots",
		"https://ct.googleapis.com/icarus/ct/v1/get-roots",
		"https://ct.googleapis.com/rocketeer/ct/v1/get-roots",
		"https://ct.googleapis.com/skydiver/ct/v1/get-roots",
	}
)

type googleCTJson struct {
	Certificates []string `json:"certificates"`
}


func googleCTCerts() ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0)

	for i := range googleCTUrls {
		resp, err := http.DefaultClient.Get(googleCTUrls[i])
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		// Decode from json
		var certs googleCTJson
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

func CT() ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0)

	add := func(cs []*x509.Certificate, err error) error {
		if err != nil {
			return err
		}
		out = append(out, cs...)
		return nil
	}

	// google
	err := add(googleCTCerts())
	if err != nil {
		return nil, err
	}

	return out, nil
}
