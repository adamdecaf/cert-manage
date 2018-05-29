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
	"bytes" 
	"crypto/x509" 
 
	"github.com/adamdecaf/extract-nss-root-certs" 
) 
 
type decoder func([]byte) ([]*x509.Certificate, error) 
 
var ( 
	decoders = []decoder{ 
		ParsePEM, 
		readNSSCerts, 
	} 
) 
 
// Decode attempts to read `bs` with a few different parsers 
// to return an array of x509 Certificates 
func Decode(bs []byte) ([]*x509.Certificate, error) { 
	for i := range decoders { 
		certs, err := decoders[i](bs) 
		if err == nil && len(certs) > 0 { 
			return certs, nil 
		} 
	} 
	return nil, nil 
} 
 
func readNSSCerts(bs []byte) ([]*x509.Certificate, error) { 
	cfg := nsscerts.Config{} 
	r := bytes.NewReader(bs) 
	return nsscerts.List(r, &cfg) 
} 
