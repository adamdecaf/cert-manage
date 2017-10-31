// +build darwin windows

package store

// On darwin and windows Chrome uses the included platform certificate store
// https://www.chromium.org/Home/chromium-security/root-ca-policy
// TODO(adam): Should we instead throw an error about this? This might not be very explicit
func ChromeStore() Store {
	return Platform()
}
