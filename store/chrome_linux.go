// +build linux

package store

// On linux chrome uses NSS
// https://www.chromium.org/Home/chromium-security/root-ca-policy
func ChromeStore() Store {
	return NssStore()
}
