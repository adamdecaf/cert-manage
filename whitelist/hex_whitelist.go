package whitelist

import (
	"crypto/x509"
	"github.com/adamdecaf/cert-manage/tools/_x509"
	"strings"
)

const (
	minimumSignatureLength = 8
)

// HexFingerprintItem matches an incoming signature (encoded in hex) against that of a certificate.
type HexFingerprintItem struct {
	Signature string // hex encoded

	Item
}

// Matches will check a given certificate against a hex signate to verify if they match or not
func (w HexFingerprintItem) Matches(c x509.Certificate) bool {
	fingerprint := _x509.GetHexSHA256Fingerprint(c)

	// Check some constraints
	if len(w.Signature) < minimumSignatureLength {
		return false
	}

	// If the whitelist has a shortened fingerprint use it as a prefix
	// Otherwise, compare their full contents
	if len(w.Signature) < len(fingerprint) {
		return strings.HasPrefix(fingerprint, w.Signature)
	}
	return w.Signature == fingerprint
}
