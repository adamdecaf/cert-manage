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
	"testing" 
) 
 
func TestCertUtil__sort(t *testing.T) { 
	certs, err := FromFile("../../testdata/lots.crt") 
	if err != nil { 
		t.Fatal(err) 
	} 
	Sort(certs) 
 
	answers := []string{ 
		"EE Certification Centre Root CA", 
		"Entrust Root Certification Authority", 
		"Entrust Root Certification Authority - EC1", 
		"Entrust Root Certification Authority - G2", 
		"Entrust.net Certification Authority (2048)", 
	} 
 
	for i := range certs { 
		sub := StringifyPKIXName(certs[i].Subject) 
		if sub != answers[i] { 
			t.Errorf("idx %d got %q", i, sub) 
		} 
	} 
} 
