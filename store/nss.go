package store

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/adamdecaf/cert-manage/whitelist"
)

// Docs:
// - https://chromium.googlesource.com/chromium/src/+/master/docs/linux_cert_management.md
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
// - https://wiki.mozilla.org/NSS_Shared_DB_And_LINUX
// - https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/tools/NSS_Tools_certutil#Listing_Certificates_in_a_Database

const (
	nssPublicURL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"
)

type nssStore struct{}

func NssStore() Store {
	return nssStore{}
}

func (s nssStore) Backup() error {
	return nil
}

func (s nssStore) List() ([]*x509.Certificate, error) {
	resp, err := http.DefaultClient.Get(nssPublicURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		e := resp.Body.Close()
		if e != nil {
			fmt.Printf("error closing nss http resp - %s\n", e)
		}
	}()

	objects, err := parseInput(resp.Body)
	if err != nil {
		return nil, err
	}

	return convertObjectsToCertificates(objects)
}

// TODO(adam): impl
func (s nssStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s nssStore) Restore(where string) error {
	return nil
}

// ====
// This code is ported from the below repo. It has been modified to work inside cert-manage
// https://github.com/agl/extract-nss-root-certs
// ====

// Copyright 2012 Google Inc. All Rights Reserved.
// Author: agl@chromium.org (Adam Langley)

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This utility parses Mozilla's certdata.txt and extracts a list of trusted
// certificates in PEM form.
//
// A current version of certdata.txt can be downloaded from:
//   https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

// object represents a collection of attributes from the certdata.txt file
// which are usually either certificates or trust records.
type object struct {
	attrs        map[string]attribute
	startingLine int // the line number that the object started on.
}

type attribute struct {
	attrType string
	value    []byte
}

// parseInput parses a certdata.txt file into it's license blob, the CVS id (if
// included) and a set of Objects.
func parseInput(inFile io.Reader) ([]*object, error) {
	in := bufio.NewReader(inFile)
	var lineNo int

	var currentObject *object
	var beginData bool

	objects := make([]*object, 0)

	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if line == "BEGINDATA" {
			beginData = true
			continue
		}

		words := strings.Fields(line)
		var value []byte
		if len(words) == 2 && words[1] == "MULTILINE_OCTAL" {
			startingLine := lineNo
			var ok bool
			value, ok = readMultilineOctal(in, &lineNo)
			if !ok {
				return nil, fmt.Errorf("Failed to read octal value starting at line %d", startingLine)
			}
		} else if len(words) < 3 {
			return nil, fmt.Errorf("Expected three or more values on line %d, but found %d", lineNo, len(words))
		} else {
			value = []byte(strings.Join(words[2:], " "))
		}

		if words[0] == "CKA_CLASS" {
			// Start of a new object.
			if currentObject != nil {
				objects = append(objects, currentObject)
			}
			currentObject = new(object)
			currentObject.attrs = make(map[string]attribute)
			currentObject.startingLine = lineNo
		}
		if currentObject == nil {
			return nil, fmt.Errorf("Found attribute on line %d which appears to be outside of an object", lineNo)
		}
		currentObject.attrs[words[0]] = attribute{
			attrType: words[1],
			value:    value,
		}
	}

	if !beginData {
		return nil, fmt.Errorf("Read whole input and failed to find BEGINDATA")
	}
	if currentObject != nil {
		objects = append(objects, currentObject)
	}

	return objects, nil
}

// convertObjectsToCertificates takes a series of PEM encoded certificates
// and returns x509.Certificate for trusted certificates
func convertObjectsToCertificates(objects []*object) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0)

	certs := filterObjectsByClass(objects, "CKO_CERTIFICATE")
	trusts := filterObjectsByClass(objects, "CKO_NSS_TRUST")

	for i := range certs {
		derBytes := certs[i].attrs["CKA_VALUE"].value
		hash := sha1.New()
		_, err := hash.Write(derBytes)
		if err != nil {
			return nil, err
		}
		digest := hash.Sum(nil)

		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			// This is known to occur because of a broken certificate in NSS.
			// https://bugzilla.mozilla.org/show_bug.cgi?id=707995
			return nil, fmt.Errorf("Failed to parse certificate starting on line %d: %s", certs[i].startingLine, err)
		}

		// TODO(agl): wtc tells me that Mozilla might get rid of the
		// SHA1 records in the future and use issuer and serial number
		// to match trust records to certificates (which is what NSS
		// currently uses). This needs some changes to the crypto/x509
		// package to keep the raw names around.

		var trust *object
		for _, possibleTrust := range trusts {
			if bytes.Equal(digest, possibleTrust.attrs["CKA_CERT_SHA1_HASH"].value) {
				trust = possibleTrust
				break
			}
		}

		if trust == nil {
			return nil, fmt.Errorf("No trust found for certificate object starting on line %d (sha1: %x)", certs[i].startingLine, digest)
		}

		trustType := trust.attrs["CKA_TRUST_SERVER_AUTH"].value
		if len(trustType) == 0 {
			return nil, fmt.Errorf("No CKA_TRUST_SERVER_AUTH found in trust starting at line %d", trust.startingLine)
		}

		var trusted bool
		switch string(trustType) {
		case "CKT_NSS_NOT_TRUSTED":
			// An explicitly distrusted cert
			trusted = false
		case "CKT_NSS_TRUSTED_DELEGATOR":
			// A cert trusted for issuing SSL server certs.
			trusted = true
		case "CKT_NSS_TRUST_UNKNOWN", "CKT_NSS_MUST_VERIFY_TRUST":
			// A cert not trusted for issuing SSL server certs, but is trusted for other purposes.
			trusted = false
		default:
			return nil, fmt.Errorf("Unknown trust value '%s' found for trust record starting on line %d", trustType, trust.startingLine)
		}

		if trusted {
			out = append(out, cert)
		}
	}

	return out, nil
}

// filterObjectsByClass returns a subset of in where each element has the given
// class.
func filterObjectsByClass(in []*object, class string) (out []*object) {
	for _, object := range in {
		if string(object.attrs["CKA_CLASS"].value) == class {
			out = append(out, object)
		}
	}
	return
}

// readMultilineOctal converts a series of lines of octal values into a slice
// of bytes.
func readMultilineOctal(in *bufio.Reader, lineNo *int) ([]byte, bool) {
	var value []byte

	for line, eof := getLine(in, lineNo); !eof; line, eof = getLine(in, lineNo) {
		if line == "END" {
			return value, true
		}

		for _, octalStr := range strings.Split(line, "\\") {
			if len(octalStr) == 0 {
				continue
			}
			v, err := strconv.ParseUint(octalStr, 8, 8)
			if err != nil {
				return nil, false
			}
			value = append(value, byte(v))
		}
	}

	// Missing "END"
	return nil, false
}

// getLine reads the next line from in, aborting in the event of an error.
func getLine(in *bufio.Reader, lineNo *int) (string, bool) {
	*lineNo++
	line, isPrefix, err := in.ReadLine()
	if err == io.EOF {
		return "", true
	}
	if err != nil || isPrefix {
		return "", true
	}
	return string(line), false
}
