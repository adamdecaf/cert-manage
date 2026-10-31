// Copyright 2018 Adam Shannon
//
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

package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

// pemParseWarn is where ParsePEM writes skip warnings. Tests may replace it.
var pemParseWarn io.Writer = os.Stderr

// ParsePEM extracts certificates from a PEM bundle. Each CERTIFICATE block is
// parsed independently. Unparsable blocks (for example those with a negative
// serial number) are skipped with a warning to stderr so one bad entry cannot
// abort the rest of the bundle. Non-CERTIFICATE PEM types are ignored.
func ParsePEM(blob []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *pem.Block
	n := 0
	for {
		block, blob = pem.Decode(blob)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		n++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(pemParseWarn, "certutil: skipping PEM block %d: %v\n", n, err)
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
