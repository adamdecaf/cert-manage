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
 
package gen 
 
import ( 
	"net/url" 
	"reflect" 
	"sync" 
	"testing" 
	"time" 
 
	"github.com/adamdecaf/cert-manage/pkg/certutil" 
) 
 
func TestGen__caSigns(t *testing.T) { 
	certs, err := certutil.FromFile("../../../testdata/example.crt") 
	if err != nil { 
		t.Fatal(err) 
	} 
	ca := CA{ 
		Certificate: certs[0], 
	} 
 
	// we didn't tell ca that it signs anything, yet 
	if ca.signs("") || ca.signs("google.com") { 
		t.Error("nope, shouldn't say it signs anything yet") 
	} 
 
	// add signers 
	ca.addDNSName("google.com") 
	ca.addDNSName("*.gmail.com") 
	ca.addDNSName("google.com") 
	ca.addDNSName("*.gmail.com") 
 
	// check we didn't add duplicates 
	if len(ca.DNSNames) != 2 { 
		t.Errorf("got %d", len(ca.DNSNames)) 
	} 
 
	// Check signers now 
	cases := []struct { 
		dnsName string 
		valid   bool 
	}{ 
		{"yahoo.com", false}, 
		{"mail.yahoo.com", false}, 
		{"google.com", true}, 
		{"mail.gmail.com", true}, 
		{"foo.mail.google.com", false}, 
		{"foo.mail.gmail.com", false}, 
	} 
	for i := range cases { 
		if res := ca.signs(cases[i].dnsName); res != cases[i].valid { 
			t.Errorf("%q got %v wanted %v", cases[i].dnsName, res, cases[i].valid) 
		} 
	} 
} 
 
func TestGen__caFind(t *testing.T) { 
	certs, err := certutil.FromFile("../../../testdata/banno.com") 
	if err != nil { 
		t.Fatal(err) 
	} 
	authorities := CAs{} 
	ca, exists := authorities.find(certs[0]) 
	if exists { 
		t.Error("ca couldn't have existed") 
	} 
	if ca.Fingerprint != certutil.GetHexSHA256Fingerprint(*certs[0]) { 
		t.Errorf("bad fingerprint, got %q", ca.Fingerprint) 
	} 
 
	if len(ca.DNSNames) != 0 { 
		t.Errorf("somehow DNSNames were added..") 
	} 
 
	// manually call .addDNSName() and check 
	ca.addDNSName("*.banno.com") 
	ca.addDNSName("banno.com") 
 
	ans := []string{"*.banno.com", "banno.com"} 
	if !reflect.DeepEqual(ca.DNSNames, ans) { 
		t.Errorf("got %q", ca.DNSNames) 
	} 
 
	// check .findSigners 
	if res := authorities.findSigners("banno.com"); len(res) != 1 { 
		t.Error("expectd to find signer") 
	} 
	if res := authorities.findSigners("api.banno.com"); len(res) != 1 { 
		t.Error("expectd to find signer") 
	} 
	if res := authorities.findSigners("google.com"); len(res) != 0 { 
		t.Error("shouldn't have found signer") 
	} 
} 
 
func TestGen__getChain(t *testing.T) { 
	cases := []string{ 
		"https://google.com", 
		"https://google.com:443", 
	} 
	for i := range cases { 
		u, _ := url.Parse(cases[i]) 
		c := getChain(u, nil) 
		if len(c) == 0 { 
			t.Error("expected cert chain") 
		} 
		for i := range c { 
			if c[i] == nil { 
				t.Fatalf("%v has nil-cert", c) 
			} 
		} 
	} 
} 
 
func TestGen__gate(t *testing.T) { 
	workers := newgate(2) 
 
	// three timeslots, easy to fill in 
	var w1 time.Time 
	var w2 time.Time 
	var w3 time.Time 
 
	// start workers 
	wg := sync.WaitGroup{} 
	wg.Add(3) 
 
	// first 
	workers.begin() 
	go func() { 
		w1 = time.Now() 
		time.Sleep(100 * time.Millisecond) 
		workers.done() 
		wg.Done() 
	}() 
 
	// second 
	workers.begin() 
	go func() { 
		w2 = time.Now() 
		time.Sleep(100 * time.Millisecond) 
		workers.done() 
		wg.Done() 
	}() 
 
	// third 
	go func() { 
		workers.begin() 
		w3 = time.Now() 
		workers.done() 
		wg.Done() 
	}() 
 
	wg.Wait() 
	// check (w3 should come last) 
	if w1.After(w3) || w2.After(w3) { 
		t.Errorf("w1=%q > w3=%q", w1, w3) 
	} 
	if w2.After(w3) { 
		t.Errorf("w2=%q > w3=%q", w2, w3) 
	} 
	if w1.IsZero() || w2.IsZero() || w3.IsZero() { 
		t.Errorf("can't be zero: w1=%q, w2=%q, w3=%q", w1, w2, w3) 
	} 
} 
