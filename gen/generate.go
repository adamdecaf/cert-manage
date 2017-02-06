package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"flag"
	"io/ioutil"
	"github.com/adamdecaf/cert-manage/cmd"
	"github.com/adamdecaf/cert-manage/certs"
	"path/filepath"
	"strings"
	"os"
)

var (
	// Google entities
	google = flag.Bool("google", false, "Add google's owned CA certs")

	// Digicert
	digicert = flag.Bool("digicert", false, "Add Digicert CA certs")

	// Visa
	visa = flag.Bool("visa", false, "Add Visa CA certs")

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
	if file == nil || strings.TrimSpace(*file) == "" {
		fmt.Println("Missing whitelist path.")
		os.Exit(1)
	}

	// Accumulate all certs for the whitelist
	whitelisted := make([]*x509.Certificate, 0)

	errors := make([]error, 0)

	// Google
	if set(google) {
		cs, err := Google()
		if err != nil {
			errors = append(errors, err)
		}
		whitelisted = append(whitelisted, cs...)
	}

	// Digicert
	if set(digicert) {
		cs, err := Digicert()
		if err != nil {
			errors = append(errors, err)
		}
		whitelisted = append(whitelisted, cs...)
	}

	// Visa
	if set(visa) {
		cs, err := Visa()
		if err != nil {
			errors = append(errors, err)
		}
		whitelisted = append(whitelisted, cs...)
	}

	// Print any errors generated
	for _, err := range errors {
		fmt.Println(err)
	}

	// Distinct (and sort) all whitelist items
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

	// todo: sort json so we don't get noisy diffs on every re-gen

	// marshal to json
	b, err := json.Marshal(list)
	if err != nil {
		fmt.Println("error:", err)
	}

	// write to the file file
	path, err := filepath.Abs(*file)
	if err != nil {
		fmt.Println(err)
	}

	err = ioutil.WriteFile(path, b, 0644)
	if err != nil {
		fmt.Println("error:", err)
	}

	// Exit non-zero if there were errors
	if len(errors) != 0 {
		os.Exit(1)
	}
}

func set(b *bool) bool {
	return b != nil && *b
}
