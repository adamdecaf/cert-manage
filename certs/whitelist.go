package certs

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

const (
	MinimumSignatureLength = 8
)

// `WhitelistItem` can be compared against an x509 Certificate to see if the cert represents
// some value presented by the whitelist item. This is useful in comparing specific fields of
// Certificate against multiple whitelist candidates.
type WhitelistItem interface {
	Matches(x509.Certificate) bool
}

// HexSignatureWhitelistItem matches an incoming signature (encoded in hex) against that of a certificate.
// todo: combine usage with print.go's hex encoding
type HexSignatureWhitelistItem struct {
	Signature string // hex encoded

	WhitelistItem
}
func (w HexSignatureWhitelistItem) Matches(c x509.Certificate) bool {
	// Grab the cert's hex encoding
	ss := sha256.New()
	ss.Write(c.RawSubjectPublicKeyInfo)
	fingerprint := hex.EncodeToString(ss.Sum(nil))

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

// ``
func NewWhitelistItems(path string) ([]WhitelistItem, error) {
	if !validWhitelistPath(path) {
		return nil, fmt.Errorf("The path '%s' doesn't seem to contain a whitelist.", path)
	}
	// todo
	var items []WhitelistItem
	items = append(items, WhitelistItem{})
	return items, nil
}

// validWhitelistPath verifies that the given whitelist filepath is properly defined
// and exists on the given filesystem.
func validWhitelistPath(path string) bool {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		fmt.Printf("expanding the path failed with: %s\n", err)
		return false
	}

	valid := true
	isFlag := strings.HasPrefix(path, "-")

	if len(path) == 0 || isFlag {
		valid = false
		fmt.Printf("The given whitelist file path '%s' doesn't look correct.\n", path)
		if isFlag {
			fmt.Println("The path looks like a cli flag, -whitelist requires a path to the whitelist file.")
		} else {
			fmt.Println("The given whitelist file path is empty.")
		}
	}

	_, err = os.Stat(path)
	if err != nil {
		valid = false
		fmt.Printf("The path %s doesn't seem to exist.\n", path)
	}

	return valid
}
