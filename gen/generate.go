package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"flag"
	"io/ioutil"
	"github.com/adamdecaf/cert-manage/cmd"
	"github.com/adamdecaf/cert-manage/certs"
	"strings"
	"os"
)

var (
	// Google entities
	google = flag.Bool("google", false, "Add google's owned CA certs")
	googleSuggested = flag.Bool("google-suggested", false, "Add google's suggested CA certs list")

	// meta
	file = flag.String("file", "", "Whitelist output file location")
	print = flag.Bool("print", false, "Print the certs that will be put into the whitelist json")
	version = flag.Bool("version", false, "Output the version information")
)

const Version = "0.0.1-dev"

func main() {
	flag.Parse()

	if set(version) {
		fmt.Printf("gen-whitelist: %s\n", Version)
		return
	}

	// Check flags
	// todo: reuse whitelist.go's validWhitelistPath(..) func here also
	if file == nil || strings.TrimSpace(*file) == "" {
		fmt.Println("Missing whitelist path.")
		os.Exit(1)
	}

	// Accumulate all certs for the whitelist
	whitelisted := make([]*x509.Certificate, 0)

	// Google
	if set(google) {
		whitelisted = append(whitelisted, Google()...)
	}
	if set(googleSuggested) {
		whitelisted = append(whitelisted, GoogleSuggestedRoots()...)
	}

	// Distinct all whitelist items
	// todo

	if *print {
		cmd.PrintCerts(whitelisted, "table")
	}

	// generate json whitelist
	sigs := make([]string, len(whitelisted))
	for i,c := range whitelisted {
		// todo: ok, is it a signature or a fingerprint?
		fingerprint := certs.GetHexSHA256Fingerprint(*c)
		sigs[i] = fingerprint
	}

	list := certs.JsonWhitelist{
		Signatures: certs.JsonSignatures{
			Hex: sigs,
		},
	}

	// marshal to json
	b, err := json.Marshal(list)
	if err != nil {
		fmt.Println("error:", err)
	}

	// write to the file
	// todo: expand_path
	err = ioutil.WriteFile(*file, b, 0644)
	if err != nil {
		fmt.Println("error:", err)
	}
}

func set(b *bool) bool {
	return b != nil && *b
}
