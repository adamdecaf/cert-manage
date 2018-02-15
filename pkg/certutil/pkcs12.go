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
	// "errors"

	"golang.org/x/crypto/pkcs12"
)

func DecodePKCS12(bs []byte, pass string) (*x509.Certificate, error) {
	_, cert, err := pkcs12.Decode(bs, pass)
	return cert, err

	// TODO(adam): https://github.com/golang/go/issues/23499
	// out, err := pkcs12.ToPEM(bs, pass)
	// if err != nil {
	// 	return nil, err
	// }
	// if out == nil {
	// 	return nil, errors.New("empty pem block")
	// }
	// if len(out) > 0 {
	// 	p, err := Parse(out[0].Bytes)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return p[0], nil
	// }
	// return nil, nil
}
