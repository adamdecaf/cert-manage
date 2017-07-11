package _x509

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// https://tools.ietf.org/html/rfc7250
func GetHexSHA256Fingerprint(c x509.Certificate) string {
	// Grab the cert's hex encoding
	ss := sha256.New()
	ss.Write(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(ss.Sum(nil))
}

func StringifyPubKeyAlgo(p x509.PublicKeyAlgorithm) string {
	res := "Unknown"
	switch p {
	case x509.RSA:
		res = "RSA"
	case x509.DSA:
		res = "DSA"
	case x509.ECDSA:
		res = "ECDSA"
	}
	return res
}
