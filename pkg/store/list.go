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

package store

import (
	"crypto/x509"
)

type ListOptions struct {
	// Include "trusted" certificates
	// This represents what'a good acting application or would return
	Trusted bool

	// Include certificates specifically untrusted by a user/admin
	Untrusted bool

	// Include certificates which are revoked
	Revoked bool

	// Include certificates which are expired
	Expired bool
}

type Lister interface {
	// List returns the currently trusted X509 certificates contained
	// within the cert store
	List(opts *ListOptions) ([]*x509.Certificate, error)
}
