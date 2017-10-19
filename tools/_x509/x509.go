package _x509

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

func GetHexSHA1Fingerprint(c x509.Certificate) string {
	ss := sha1.New()
	ss.Write(c.Raw)
	return hex.EncodeToString(ss.Sum(nil))
}

func GetHexSHA256Fingerprint(c x509.Certificate) string {
	ss := sha256.New()
	ss.Write(c.Raw)
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
