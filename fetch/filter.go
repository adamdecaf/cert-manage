package fetch

import (
	"crypto/x509"
	"github.com/adamdecaf/cert-manage/whitelist"
)

// Keep certificates that match the fingerprint whitelist
func filter(fingerprints []string, cs []*x509.Certificate) []*x509.Certificate {
	// If we don't have fingerprints to check against, just return all certs.
	if len(fingerprints) == 0 {
		return cs
	}

	wh := make([]whitelist.Item, len(fingerprints))
	for i := range fingerprints {
		wh[i] = whitelist.HexFingerprintItem{Signature: fingerprints[i]}
	}
	return whitelist.Filter(cs, wh)
}
