package old

// package certs

// import (
// 	"crypto/x509"
// 	"fmt"
// 	"encoding/json"
// 	"github.com/adamdecaf/cert-manage/file"
// 	"io/ioutil"
// 	"time"
// 	"strings"
// )

// const (
// 	MinimumSignatureLength = 8
// 	NotAfterFormat = "2006-01-02 03:04:05"
// )

// // Matches a Certificate's Issuer CommonName
// type IssuersCommonNameWhitelistItem struct {
// 	Name string
// 	WhitelistItem
// }
// func (w IssuersCommonNameWhitelistItem) Matches(c x509.Certificate) bool {
// 	if len(strings.TrimSpace(w.Name)) > 0 {
// 		return strings.Contains(c.Subject.CommonName, w.Name)
// 	}
// 	return false
// }

// // Matches the NotAfter on a Certificate
// // This will accept certificates whose NotAfter is before or the same as the
// // given value in the WhitelistItem
// type NotAfterWhitelistItem struct {
// 	Time time.Time
// 	WhitelistItem
// }
// func (w NotAfterWhitelistItem) Matches(c x509.Certificate) bool {
// 	return c.NotAfter.Before(w.Time) || c.NotAfter.Equal(w.Time)
// }

// // Json structure in struct form
// type JsonWhitelist struct {
// 	Signatures JsonSignatures `json:"Signatures,omitempty"`
// 	Issuers []JsonIssuers `json:"Issuers,omitempty"`
// 	Time JsonTime `json:"Time,omitempty"`
// }
// type JsonSignatures struct {
// 	Hex []string `json:"Hex"`
// }
// type JsonIssuers struct {
// 	CommonName string `json:"CommonName"`
// }
// type JsonTime struct {
// 	NotAfter string `json:"NotAfter"`
// }

// // FromFile reads a whitelist file and parses it into WhitelistItems
// func FromFile(path string) ([]WhitelistItem, error) {
// 	if !validWhitelistPath(path) {
// 		return nil, fmt.Errorf("The path '%s' doesn't seem to contain a whitelist.", path)
// 	}

// 	// read file
// 	b, err := ioutil.ReadFile(path)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var parsed JsonWhitelist
// 	err = json.Unmarshal(b, &parsed)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Read parsed format into structs
// 	var items []WhitelistItem
// 	for _,s := range parsed.Signatures.Hex {
// 		items = append(items, HexFingerprintWhitelistItem{Signature: s})
// 	}
// 	for _,i := range parsed.Issuers {
// 		items = append(items, IssuersCommonNameWhitelistItem{Name: i.CommonName})
// 	}
// 	if t := parsed.Time.NotAfter; len(strings.TrimSpace(t)) > 0 {
// 		when, err := time.Parse(NotAfterFormat, t)
// 		if err != nil {
// 			return nil, err
// 		}
// 		items = append(items, NotAfterWhitelistItem{Time: when})
// 	}

// 	return items, nil
// }

// // validWhitelistPath verifies that the given whitelist filepath is properly defined
// // and exists on the given filesystem.
// func validWhitelistPath(path string) bool {
// 	if !file.Exists(path) {
// 		fmt.Printf("The path %s doesn't seem to exist.\n", path)
// 	}

// 	isFlag := strings.HasPrefix(path, "-")
// 	if len(path) == 0 || isFlag {
// 		fmt.Printf("The given whitelist file path '%s' doesn't look correct.\n", path)
// 		if isFlag {
// 			fmt.Println("The path looks like a cli flag, -whitelist requires a path to the whitelist file.")
// 		} else {
// 			fmt.Println("The given whitelist file path is empty.")
// 		}
// 		return false
// 	}

// 	return true
// }
