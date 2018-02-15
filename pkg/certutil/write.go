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
	"encoding/pem"
	"io/ioutil"
	"os"
)

// ToFile overwrites file at `path` with the certificates encoded in
// PEM format.
func ToFile(path string, certs []*x509.Certificate) error {
	var perms os.FileMode = 0666
	stat, err := os.Stat(path)
	if err == nil {
		perms = stat.Mode()
	}

	// write the cert(s)
	var buf bytes.Buffer
	for i := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certs[i].Raw,
		}
		if err := pem.Encode(&buf, b); err != nil {
			return err
		}
	}
	return ioutil.WriteFile(path, buf.Bytes(), perms)
}
