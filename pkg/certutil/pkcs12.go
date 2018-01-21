package certutil

import (
	"crypto/x509"
	// "errors"

	// "github.com/adamdecaf/cert-manage/pkg/pem"
	"golang.org/x/crypto/pkcs12"
)

func DecodePKCS12(bs []byte, pass string) (*x509.Certificate, error) {
	_, cert, err := pkcs12.Decode(bs, pass)
	return cert, err

	// TODO(adam): https://github.com/golang/go/issues/23499
	// out, err := pkcs12.ToPEM(bs, pass)
	// if err != nil {
	// 	return nil, err
	// }
	// if out == nil {
	// 	return nil, errors.New("empty pem block")
	// }
	// if len(out) > 0 {
	// 	p, err := pem.Parse(out[0].Bytes)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return p[0], nil
	// }
	// return nil, nil
}
