// package certs

// import (
// 	"crypto/x509"
// 	"encoding/pem"
// 	"fmt"
// )

// func ParsePEMIntoCerts(blob []byte) ([]*x509.Certificate, error) {
// 	var certs []*x509.Certificate
// 	var block *pem.Block
// 	for {
// 		block, blob = pem.Decode(blob)
// 		if block == nil {
// 			break
// 		}
// 		if block.Type == "CERTIFICATE" {
// 			cert, err := x509.ParseCertificate(block.Bytes)
// 			if err != nil {
// 				return nil, err
// 			}
// 			certs = append(certs, cert)
// 		}
// 	}
// 	if len(certs) == 0 {
// 		return nil, fmt.Errorf("unable to find certs in PEM blob")
// 	}
// 	return certs, nil
// }
