// +build darwin windows

package store

// On darwin and windows Chrome uses the included platform certificate store
// https://www.chromium.org/Home/chromium-security/root-ca-policy
func ChromeStore() Store {
	return Platform()
}
