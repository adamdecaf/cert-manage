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
	"io/ioutil" 
	"os" 
	"testing" 
) 
 
func TestCertutilPEM__write(t *testing.T) { 
	c1, err := FromFile("../../testdata/example.crt") 
	if err != nil { 
		t.Fatal(err) 
	} 
 
	// write that back, then read it again and compare 
	f, err := ioutil.TempFile("", "cert-manage") 
	// f, err := os.Create("cert-mange-pem") 
	if err != nil { 
		t.Fatal(err) 
	} 
	err = os.Chmod(f.Name(), 0666) 
	if err != nil { 
		t.Fatal(err) 
	} 
	defer os.Remove(f.Name()) 
 
	// write 
	err = ToFile(f.Name(), c1) 
	if err != nil { 
		t.Fatal(err) 
	} 
 
	// read the written certs back and compare 
	c2, err := FromFile(f.Name()) 
	if err != nil { 
		t.Fatal(err) 
	} 
	if len(c1) != len(c2) { 
		t.Fatalf("len(c1)=%d != len(c2)=%d", len(c1), len(c2)) 
	} 
	for i := range c1 { 
		if c1 == nil || c2 == nil { 
			t.Fatalf("either c1 or c2 are null\nc1=%v\nc2=%v", c1, c2) 
		} 
		f1 := GetHexSHA256Fingerprint(*c1[i]) 
		f2 := GetHexSHA256Fingerprint(*c2[i]) 
		if f1 != f2 { 
			t.Fatalf("f1=%q != f2=%q", f1, f2) 
		} 
	} 
} 
