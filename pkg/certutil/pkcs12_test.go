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
	"fmt" 
	"io/ioutil" 
	"testing" 
) 
 
func TestCertutil__decodePKCS12(t *testing.T) { 
	t.Skip("broken upstream See https://github.com/golang/go/issues/23499") 
 
	bs, err := ioutil.ReadFile("../../testdata/cert.pfx") 
	if err != nil { 
		t.Fatal(err) 
	} 
	cert, err := DecodePKCS12(bs, "Password") 
	if err != nil { 
		t.Fatal(err) 
	} 
	if cert == nil { 
		t.Fatal("nil cert") 
	} 
 
	// Subject: C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Root Certificate Authority 2010 
	// Serial: 28:cc:3a:25:bf:ba:44:ac:44:9a:9b:58:6b:43:39:aa (hex?) 54229527761073585954067062875972909482 (...decimal?) 
 
	// Subject: Microsoft Corporation 
	// Issuer: Microsoft Corporation 
 
	// df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e 
	// SHA256 Fingerprint=DF:54:5B:F9:19:A2:43:9C:36:98:3B:54:CD:FC:90:3D:FA:4F:37:D3:99:6D:8D:84:B4:C3:1E:EC:6F:3C:16:3E 
 
	// Not Before: Jun 23 21:57:24 2010 GMT 
	// Not After : Jun 23 22:04:01 2035 GMT 
	// CA:TRUE 
 
	fmt.Println(cert) 
} 
