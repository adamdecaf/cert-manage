package whitelist

import (
	"crypto/x509"
	"strings"

	"github.com/adamdecaf/cert-manage/tools/_x509"
)

const (
	minimumFingerprintLength = 8
)

// fingerprint matches an incoming certificate's fingerprint (in hex)
type fingerprint string

func (f fingerprint) String() string {
	return string(f)
}

// Matches will check a given certificate against a hex encoded fingerprint
func (f fingerprint) Matches(c x509.Certificate) bool {
	fp := _x509.GetHexSHA256Fingerprint(c)

	// Check some constraints
	if len(f) < minimumFingerprintLength {
		return false
	}

	// If the whitelist has a shortened fingerprint use it as a prefix
	// Otherwise, compare their full contents
	if len(f) < len(fp) {
		return strings.HasPrefix(fp, f.String())
	}
	return f.String() == fp
}
