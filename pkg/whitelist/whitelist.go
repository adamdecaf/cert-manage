package whitelist

import (
	"crypto/x509"
	"encoding/json"
	"io/ioutil"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
)

// Whitelist is the structure holding various `item` types that match against
// x509 certificates
type Whitelist struct {
	// sha256 fingerprints
	Fingerprints []string `json:"Fingerprints,omitempty"`
}

// Matches checks a given x509 certificate against the criteria and
// returns if it's matched by an item in the whitelist
func (w Whitelist) Matches(inc *x509.Certificate) bool {
	if inc == nil {
		return false
	}
	fp := certutil.GetHexSHA256Fingerprint(*inc)
	for i := range w.Fingerprints {
		if w.Fingerprints[i] == fp {
			return true
		}
	}
	return false
}

// MatchesAll checks if a given list of certificates all match against a whitelist
func (w Whitelist) MatchesAll(cs []*x509.Certificate) bool {
	for i := range cs {
		if !w.Matches(cs[i]) {
			return false
		}
	}
	return true
}

func FromCertificates(certs []*x509.Certificate) Whitelist {
	wh := Whitelist{}
	for i := range certs {
		if certs[i] == nil {
			continue
		}
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		wh.Fingerprints = append(wh.Fingerprints, fp)
	}
	return wh
}

// FromFile reads a whitelist file and parses it into items
func FromFile(path string) (Whitelist, error) {
	wh := Whitelist{}
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return wh, err
	}
	err = json.Unmarshal(b, &wh)
	return wh, err
}

// ToFile take a Whitelist, encods it to json and writes the result
func (w Whitelist) ToFile(path string) error {
	out, err := json.Marshal(&w)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, out, 0644)
}
