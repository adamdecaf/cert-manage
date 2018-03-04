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
	"sync"
)

// cert is an internal object for pre-computing the fingerprint associated to a certificate
type cert struct {
	certificate *x509.Certificate
	fingerprint string
}

// Pool represents an append-only collection of x509 Certificates. There are no nessary connections
// between the certificates, except that each will only appear once in the pool.
type Pool struct {
	mu    sync.RWMutex // protectes all fields
	certs []*cert
}

// Add will include the given certificate into the pool if it does
// not exist already
func (p *Pool) Add(c *x509.Certificate) {
	fp := GetHexSHA256Fingerprint(*c)

	p.mu.RLock()
	for i := range p.certs {
		if p.certs[i].fingerprint == fp {
			p.mu.RUnlock() // unlock first
			return
		}
	}
	p.mu.RUnlock() // need to unlock, since we didn't return early
	p.mu.Lock()    // relock for writes
	defer p.mu.Unlock()

	// we didn't find the cert, so let's add it
	p.certs = append(p.certs, &cert{
		certificate: c,
		fingerprint: fp,
	})
}

// GetCertificates returns all x509.Certificate objects included in the pool
func (p *Pool) GetCertificates() []*x509.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()

	certs := make([]*x509.Certificate, len(p.certs))
	for i := range p.certs {
		certs[i] = p.certs[i].certificate
	}
	return certs
}
