package whitelist

import (
	"crypto/x509"
	"strings"
	"github.com/adamdecaf/cert-manage/tools/_x509"
)

const (
	MinimumSignatureLength = 8
)

// HexFingerprintWhitelistItem matches an incoming signature (encoded in hex) against that of a certificate.
type HexFingerprintWhitelistItem struct {
	Signature string // hex encoded

	WhitelistItem
}
func (w HexFingerprintWhitelistItem) Matches(c x509.Certificate) bool {
	fingerprint := _x509.GetHexSHA256Fingerprint(c)

	// Check some constraints
	if len(w.Signature) < MinimumSignatureLength {
		return false
	}

	// If the whitelist has a shortened fingerprint use it as a prefix
	// Otherwise, compare their full contents
	if len(w.Signature) < len(fingerprint) {
		return strings.HasPrefix(fingerprint, w.Signature)
	}
	return w.Signature == fingerprint
}
