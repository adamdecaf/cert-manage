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
 
func TestCertutilPEM__single(t *testing.T) { 
	certificates, err := FromFile("../../testdata/example.crt") 
	if err != nil { 
		t.Fatal(err) 
	} 
	if len(certificates) != 1 { 
		t.Fatal("Found != 1 certs in example.crt") 
	} 
 
	// match a field on the cert 
	crls := certificates[0].CRLDistributionPoints 
	if len(crls) != 1 { 
		t.Fatal("Found != 1 crls in example.crt") 
	} 
	if crls[0] != "http://certificates.starfieldtech.com/repository/sfroot.crl" { 
		t.Fatalf("found other crl(s) (%s) in example.crt", crls) 
	} 
} 
 
func TestCertutilPEM__multiple(t *testing.T) { 
	certificates, err := FromFile("../../testdata/lots.crt") 
	if err != nil { 
		t.Fatal(err) 
	} 
	if len(certificates) != 5 { 
		t.Fatal("Found != 5 certs in example.crt") 
	} 
} 
