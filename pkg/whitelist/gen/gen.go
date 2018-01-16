package gen

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var (
	maxWorkers = 25
)

// CA holds the x509 certificate representing a signer of another x509
// certificate encountered.
type CA struct {
	Certificate *x509.Certificate
}

type chain []*x509.Certificate

func (c chain) getRoot() *x509.Certificate {
	// TODO(adam): Should this grab all CA:TRUE certificates instead?
	// Maybe call it `getCAChain()` then?
	return c[len(c)-1] // last item in slice
}

// FindCACertificates accepts a slice of urls (expected to be "large") and
// finds all the CA certificates signing the urls.
//
// Only https:// urls are included
//
// URLs are grouped by their full hostname and a connection is established
// to retrieve a certificate, whose signer is looked up and retrieved. (TODO: CT logs?)
func FindCACertificates(urls []*url.URL) ([]*CA, error) {
	// setup worker pool
	workers := newgate(maxWorkers)

	// Grab unique hostnames from urls
	// Do this in a naive way with a RWMutex around a map[string]chain
	mu := sync.RWMutex{}
	// TODO(adam): We should be smarter about not re-grabbing certificates if
	// we already found one covered by SAN, wildcard, etc
	hostChains := make(map[string]chain, 0)

	wg := sync.WaitGroup{}
	for i := range urls {
		wg.Add(1)

		go func(wrk *gate, u *url.URL) {
			defer wg.Done()

			if u.Scheme != "https" {
				return
			}

			// grab a worker slot
			workers.begin()

			mu.RLock()
			_, exists := hostChains[u.Host]
			mu.RUnlock()

			if !exists {
				chain := getChain(u)
				if len(chain) > 0 {
					mu.Lock()
					hostChains[u.Host] = chain
					mu.Unlock()
				}
			}

			// cleanup
			workers.done()
		}(workers, urls[i])
	}

	wg.Wait()

	// Build model for return
	var cas []*CA
	for _, v := range hostChains {
		cas = append(cas, &CA{
			Certificate: v.getRoot(),
		})
	}
	return cas, nil
}

var (
	// https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
	client = &http.Client{
		// Never follow redirects, return body
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			},
			TLSHandshakeTimeout:   1 * time.Minute,
			IdleConnTimeout:       1 * time.Minute,
			ResponseHeaderTimeout: 1 * time.Minute,
			ExpectContinueTimeout: 1 * time.Minute,
			MaxIdleConns:          maxWorkers,
		},
		Timeout: 30 * time.Second,
	}
)

// Make as little of a connection as needed to get TLS handshake complete and
// server certificates returned.
func getChain(u *url.URL) chain {
	resp, err := client.Get(u.String())
	if err != nil {
		return nil // ignore error
	}
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()
	return resp.TLS.PeerCertificates
}

type gate struct {
	c chan struct{}
}

func (g gate) begin() {
	g.c <- struct{}{}
}
func (g gate) done() {
	select {
	case <-g.c:
	default:
		panic("invalid state")
	}
}
func newgate(n int) *gate {
	return &gate{
		c: make(chan struct{}, n),
	}
}
