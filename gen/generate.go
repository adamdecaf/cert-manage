package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/adamdecaf/cert-manage/cmd"
	"github.com/adamdecaf/cert-manage/certs"
	"os"
)

func main() {
	whitelisted := make([]*x509.Certificate, 0)

	// Add google certs
	whitelisted = append(whitelisted, Google()...)
	// whitelisted = append(whitelisted, TrustedCommunityRoots())

	cmd.PrintCerts(whitelisted, "table")

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
	os.Stdout.Write(b)
}
