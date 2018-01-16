package gen

import (
	"net/url"
	"sync"
	"testing"
	"time"
)

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
