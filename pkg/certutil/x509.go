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
	"crypto/dsa" //nolint:staticcheck // DSA still appears in legacy certificates
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

func GetHexSHA1Fingerprint(c x509.Certificate) string {
	ss := sha1.New()
	n, err := ss.Write(c.Raw)
	if err != nil {
		panic(fmt.Sprintf("error writing %s: %v", c.Subject.String(), err)) //nolint:forbidigo
	}
	if n == 0 {
		panic(fmt.Sprintf("no bytes written for %s", c.Subject.String())) //nolint:forbidigo
	}
	return hex.EncodeToString(ss.Sum(nil))
}

func GetHexSHA256Fingerprint(c x509.Certificate) string {
	ss := sha256.New()
	n, err := ss.Write(c.Raw)
	if err != nil {
		panic(fmt.Sprintf("error writing %s: %v", c.Subject.String(), err)) //nolint:forbidigo
	}
	if n == 0 {
		panic(fmt.Sprintf("no bytes written for %s", c.Subject.String())) //nolint:forbidigo
	}
	return hex.EncodeToString(ss.Sum(nil))
}

func StringifyPubKeyAlgo(p x509.PublicKeyAlgorithm) string {
	switch p {
	case x509.RSA:
		return "RSA"
	case x509.DSA:
		return "DSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	case x509.MLDSA:
		return "ML-DSA"
	default:
		return "Unknown"
	}
}

// PublicKeyInfo returns the public-key algorithm name and bit size.
func PublicKeyInfo(c *x509.Certificate) (algo string, bits int) {
	if c == nil {
		return "Unknown", 0
	}
	algo = StringifyPubKeyAlgo(c.PublicKeyAlgorithm)
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		bits = k.N.BitLen()
	case *ecdsa.PublicKey:
		if k.Curve != nil {
			if params := k.Params(); params != nil {
				bits = params.BitSize
			}
		}
	case ed25519.PublicKey:
		algo = "Ed25519"
		bits = 256
	case *dsa.PublicKey: //nolint:staticcheck // DSA still appears in legacy certificates
		if k.P != nil {
			bits = k.P.BitLen()
		}
	case *mldsa.PublicKey:
		params := k.Parameters()
		algo = params.String()
		switch params {
		case mldsa.MLDSA44():
			bits = 128
		case mldsa.MLDSA65():
			bits = 192
		case mldsa.MLDSA87():
			bits = 256
		}
	}
	return algo, bits
}

// FormatKeyLabel returns a compact KEY column value such as "RSA-2048".
func FormatKeyLabel(c *x509.Certificate) string {
	algo, bits := PublicKeyInfo(c)
	if bits <= 0 {
		return algo
	}
	return fmt.Sprintf("%s-%d", algo, bits)
}

// DaysUntilExpiry returns whole days from now until NotAfter (negative if expired).
// Negative fractional days round down so a cert that expired an hour ago reports -1.
func DaysUntilExpiry(c *x509.Certificate, now time.Time) int {
	if c == nil {
		return 0
	}
	return int(math.Floor(c.NotAfter.Sub(now).Hours() / 24))
}
