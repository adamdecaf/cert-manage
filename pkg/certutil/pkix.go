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
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"regexp"
	"strings"
)

var (
	oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// TODO(adam): Replace with RDSSquence.String() in g1.10
func StringifyPKIXName(name pkix.Name) (out string) {
	if len(name.OrganizationalUnit) > 0 {
		out = fmt.Sprintf("%s, %s", strings.Join(name.Organization, " "), name.OrganizationalUnit[0])
	}

	if out == "" {
		out = strings.Join(name.Organization, " ")
	}

	for i := range name.Names {
		if name.Names[i].Type.Equal(oidCommonName) {
			s, ok := name.Names[i].Value.(string)
			if ok {
				return cleanPKIXName(s)
			}
		}
	}

	return cleanPKIXName(out)
}

// Remove annoying characters from PKIX names
// e.g. newlines, line feeds, tabs, etc
func cleanPKIXName(name string) string {
	space := " "
	stripper := strings.NewReplacer("\n", space, "\r\n", space, "\t", space, "\r", space, "\f", space, "\v", space)
	name = stripper.Replace(name)

	trimmer := regexp.MustCompile(`(\s{1,})`)
	return trimmer.ReplaceAllString(name, " ")
}
