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
	"sort"
	"strings"
)

// sortableCerts is a wrapper around an array of x509 Certificates
// which implements sorting based on our StringifyPKIXName
type sortableCerts []*x509.Certificate

func (c sortableCerts) Len() int {
	return len(c)
}

func (c sortableCerts) Less(i, j int) bool {
	return strings.ToLower(StringifyPKIXName(c[i].Subject)) < strings.ToLower(StringifyPKIXName(c[j].Subject))
}

func (c sortableCerts) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func Sort(certs []*x509.Certificate) {
	sort.Sort(sortableCerts(certs))
}
