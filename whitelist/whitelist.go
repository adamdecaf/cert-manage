package whitelist

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/adamdecaf/cert-manage/tools/file"
)

// TOOD(adam): Read and review this code
// https://blog.hboeck.de/archives/888-How-I-tricked-Symantec-with-a-Fake-Private-Key.html

// item can be compared against an x509 Certificate to see if the cert represents
// some value presented by the whitelist item. This is useful in comparing specific fields of
// Certificate against multiple whitelist candidates.
type item interface {
	Matches(x509.Certificate) bool
}

// Whitelist is the structure holding various `item` types that match against
// x509 certificates
type Whitelist struct {
	fingerprints []item
}

// Matches checks a given x509 certificate against the criteria and
// returns if it's matched by an item in the whitelist
func (w Whitelist) Matches(inc *x509.Certificate) bool {
	if inc == nil {
		return false
	}

	for _, f := range w.fingerprints {
		if f.Matches(*inc) {
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

// Json structure in struct form
type jsonWhitelist struct {
	Fingerprints jsonFingerprints `json:"Fingerprints,omitempty"`
}
type jsonFingerprints struct {
	Hex []string `json:"Hex"`
}

// FromFile reads a whitelist file and parses it into items
func FromFile(path string) (Whitelist, error) {
	wh := Whitelist{}

	if !validWhitelistPath(path) {
		return wh, fmt.Errorf("The path '%s' doesn't seem to contain a whitelist.", path)
	}

	// read file
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return wh, err
	}

	var parsed jsonWhitelist
	err = json.Unmarshal(b, &parsed)
	if err != nil {
		return wh, err
	}

	// Read parsed format into structs
	for _, v := range parsed.Fingerprints.Hex {
		wh.fingerprints = append(wh.fingerprints, fingerprint(v))
	}

	return wh, nil
}

// validWhitelistPath verifies that the given whitelist filepath is properly defined
// and exists on the given filesystem.
func validWhitelistPath(path string) bool {
	if !file.Exists(path) {
		fmt.Printf("The path %s doesn't seem to exist.\n", path)
	}

	isFlag := strings.HasPrefix(path, "-")
	if path == "" || isFlag {
		fmt.Printf("The given whitelist file path '%s' doesn't look correct.\n", path)
		if isFlag {
			fmt.Println("The path looks like a cli flag, but -whitelist requires -file to the whitelist file.")
		} else {
			fmt.Println("The given whitelist file path is empty.")
		}
		return false
	}

	return true
}
