package gen

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
)

var (
	maxWorkers = 25

	debug = os.Getenv("DEBUG") != ""
)

// CA holds the x509 certificate representing a signer of another x509
// certificate encountered.
type CA struct {
	Certificate *x509.Certificate

	// pre-computed sha256 fingerprint
	Fingerprint string

	// dnsNames represents known fqdns (or wildcards) which this
	// CA has created a certificate for
	DNSNames []string
}

// signs checks if a given
func (c *CA) signs(dnsName string) bool {
	dnsName = strings.ToLower(dnsName)
	// TODO(adam): In go1.10 we can check if the cert is even allowed to sign dnsName
	for i := range c.DNSNames {
		if c.DNSNames[i] == dnsName {
			return true
		}
		// TODO(adam): crude wildcard match, it's probably wrong
		if strings.HasPrefix(c.DNSNames[i], "*.") {
			idx := strings.Index(dnsName, ".")
			if c.DNSNames[i][1:] == dnsName[idx:] {
				return true
			}
		}
	}
	return false
}
func (c *CA) addDNSNames(dnsNames []string) {
	// lowercase incoming dnsNames
	for i := range dnsNames {
		dnsNames[i] = strings.ToLower(dnsNames[i])
	}

	// Add each dnsName
	for i := range dnsNames {
		var exists bool
		for j := range c.DNSNames {
			if dnsNames[i] == c.DNSNames[j] {
				exists = true
				break
			}
		}
		if !exists {
			c.DNSNames = append(c.DNSNames, dnsNames[i])
		}
	}
}

type CAs struct {
	sync.RWMutex
	items []*CA
}

// find locates a CA certificate from our collection
// It's designed to be called first and .addDNSNames called
//
// Never returns nil, create the CA if it doesn't exist
func (c *CAs) find(inc *x509.Certificate) (ca *CA, exists bool) {
	c.RLock()
	incfp := certutil.GetHexSHA256Fingerprint(*inc)
	for i := range c.items {
		if c.items[i].Fingerprint == incfp {
			c.RUnlock()
			return c.items[i], true
		}
	}
	c.RUnlock()

	// Create a new CA and add
	c.Lock()
	ca = &CA{
		Certificate: inc,
		Fingerprint: certutil.GetHexSHA256Fingerprint(*inc),
	}
	ca.addDNSNames(inc.DNSNames)
	c.items = append(c.items, ca)
	c.Unlock()
	return ca, false
}

// findSigners locates all CA records that have signed for a given dns name
//
// There's a bug with this code in that having the same dnsName signed by
// multiple chains won't record all those paths.
//
// 2018-01-21: I'm not sure how frequent that situation is, but I can see
// this happening when dnsNames change their CA.
func (c *CAs) findSigners(dnsName string) []*CA {
	c.RLock()
	defer c.RUnlock()

	var out []*CA
	for i := range c.items {
		ca := c.items[i]
		if ca.signs(dnsName) {
			var exists bool
			for j := range out { // Add to accumulator only if we don't already have it
				if ca.Fingerprint == out[j].Fingerprint {
					exists = true
					break
				}
			}
			if !exists {
				out = append(out, ca)
				ca.addDNSNames([]string{dnsName})
			}
		}
	}
	return out
}

// chain represents a x509 certificate chain
type chain []*x509.Certificate

func (c chain) getRoot() *x509.Certificate {
	// TODO(adam): Should this grab all CA:TRUE certificates instead?
	// Maybe call it `getCAChain()` then?
	return c[len(c)-1] // last item in slice
}

func (c chain) getLeaf() *x509.Certificate {
	if len(c) == 0 {
		return nil
	}
	return c[0]
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
	authorities := CAs{}
	wg := sync.WaitGroup{}
	for i := range urls {
		wg.Add(1)

		go func(wrk *gate, u *url.URL) {
			defer wg.Done()

			// skip non https:// addresses, such as ftp, http, etc
			// and invalid Host values
			if u.Scheme != "https" || u.Host == "" {
				return
			}

			workers.begin()
			cas := authorities.findSigners(u.Host)
			if len(cas) == 0 {
				// We didn't find an existing CA, so we need to get one
				chain := getChain(u)
				if len(chain) == 0 {
					// We didn't find a chain, error perhaps?
					// TODO(adam): log or something, this is kinda bad
					return
				}

				// With a chain, cache the leaf cert
				leaf := chain.getLeaf()
				ca, exists := authorities.find(leaf) // DNSNames from leaf are added for us
				if debug && !exists {
					fmt.Printf("whitelist/gen: added %s leaf (%s)\n", u.Host, ca.Fingerprint[:16])
				}
			}
			workers.done()
		}(workers, urls[i])
	}

	wg.Wait()
	return authorities.items, nil
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

// gate is a worker pool impl
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
