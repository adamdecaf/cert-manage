// +build darwin

// security remove-trusted-cert <crt-file>
// exit code 1 and stderr of:
//  'SecTrustSettingsRemoveTrustSettings: The specified item could not be found in the keychain.'
// if the cert isn't in the keychain
//
// otherwise, it will open an alert box for the password
// is there a way to batch up removals?
//
// or, how does that work when go is exec'ing out?

// security add-trusted-cert <crt-file>
// works.

// Is there a way to disable a cert? aka mark it as "Never Trust"?
// Otherwise, we'll need to make a full backup of all certs before touching anything.
// ^ Then offer a way to mass-import all of them.

package certs

import (
	"crypto/x509"
)

func removeCert(cert x509.Certificate) *error {
	return nil
}
