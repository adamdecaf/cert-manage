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
	"crypto/sha1" 
	"crypto/sha256" 
	"crypto/x509" 
	"encoding/hex" 
) 
 
func GetHexSHA1Fingerprint(c x509.Certificate) string { 
	ss := sha1.New() 
	ss.Write(c.Raw) 
	return hex.EncodeToString(ss.Sum(nil)) 
} 
 
func GetHexSHA256Fingerprint(c x509.Certificate) string { 
	ss := sha256.New() 
	ss.Write(c.Raw) 
	return hex.EncodeToString(ss.Sum(nil)) 
} 
 
func StringifyPubKeyAlgo(p x509.PublicKeyAlgorithm) string { 
	res := "Unknown" 
	switch p { 
	case x509.RSA: 
		res = "RSA" 
	case x509.DSA: 
		res = "DSA" 
	case x509.ECDSA: 
		res = "ECDSA" 
	} 
	return res 
} 
