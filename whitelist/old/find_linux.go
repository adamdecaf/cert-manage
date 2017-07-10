// // +build linux

// package certs

// import (
// 	"crypto/x509"
// 	"fmt"
// 	"github.com/adamdecaf/cert-manage/file"
// 	"io/ioutil"
// 	"path/filepath"
// )

// // From Go's source, src/crypto/x509/root_linux.go
// var certFiles = []string {
// 	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
// 	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
// 	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
// 	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
// 	"/etc/pki/tls/cacert.pem",                           // OpenELEC
// }

// func FindCerts() ([]*x509.Certificate, error) {
// 	for i := range certFiles {
// 		path, err := filepath.Abs(certFiles[i])
// 		if err != nil && file.Exists(path) {
// 			fmt.Printf("checking %s\n", certFiles[i])

// 			bytes, err := ioutil.ReadFile(path)
// 			if err != nil {
// 				return nil, err
// 			}
// 			certs, err := ParsePEMIntoCerts(bytes)
// 			if err != nil {
// 				return nil, err
// 			}
// 			return certs, nil
// 		}
// 	}
// 	return nil, nil
// }
