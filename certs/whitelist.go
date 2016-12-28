package certs

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type WhitelistItem struct {
	// todo
	// Signature string
}

func (wh WhitelistItem) Matches(c x509.Certificate) bool {
	// todo
	return true
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
