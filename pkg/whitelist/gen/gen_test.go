package gen

import (
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/pem"
)

func TestGen__caSigns(t *testing.T) {
	certs, err := pem.FromFile("../../../testdata/example.crt")
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
	ca.addDNSNames([]string{
		"google.com", "*.gmail.com",
		"google.com", "*.gmail.com",
	})
	// check we didn't add duplicates
	if len(ca.dnsNames) != 2 {
		t.Errorf("got %d", len(ca.dnsNames))
	}

	// Check signers now
	cases := []struct {
		dnsName string
		valid bool
	}{
		{ "yahoo.com", false },
		{ "mail.yahoo.com", false },
		{ "google.com", true },
		{ "mail.gmail.com", true },
		{ "foo.mail.google.com", false },
		{ "foo.mail.gmail.com", false },
	}
	for i := range cases {
		if res := ca.signs(cases[i].dnsName); res != cases[i].valid {
			t.Errorf("%q got %v wanted %v", cases[i].dnsName, res, cases[i].valid)
		}
	}
}

func TestGen__caFind(t *testing.T) {
	certs, err := pem.FromFile("../../../testdata/banno.com")
	if err != nil {
		t.Fatal(err)
	}
	authorities := CAs{}
	ca, exists := authorities.find(certs[0])
	if exists {
		t.Error("ca couldn't have existed")
	}
	if ca.fingerprint != certutil.GetHexSHA256Fingerprint(*certs[0]) {
		t.Errorf("bad fingerprint, got %q", ca.fingerprint)
	}

	if len(ca.dnsNames) != 2 {
		t.Errorf("got %d", len(ca.dnsNames))
	}
	ans := []string{"*.banno.com", "banno.com"}
	if !reflect.DeepEqual(ca.dnsNames, ans) {
		t.Errorf("got %q", ca.dnsNames)
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
	u, _ := url.Parse("https://google.com")
	c := getChain(u)
	if len(c) == 0 {
		t.Error("expected cert chain")
	}
	for i := range c {
		if c[i] == nil {
			t.Fatalf("%v has nil-cert", c)
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
