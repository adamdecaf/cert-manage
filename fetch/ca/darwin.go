package ca

// // +build darwin

// package certs

// import (
// 	"crypto/x509"
// 	"os/exec"
// )

// // Docs
// // - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html

// // todo: find and show each cert's trust status

// func FindCerts() ([]*x509.Certificate, error) {
// 	b, err := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p").Output()
// 	if err != nil {
// 		return nil, err
// 	}

// 	certs, err := ParsePEMIntoCerts(b)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return certs, nil
// }
