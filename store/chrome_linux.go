// +build linux

package store

// TODO(adam): impl
func chromeCert8Locations() []string {
	return nil
}

// On linux chrome uses NSS
// https://www.chromium.org/Home/chromium-security/root-ca-policy
func ChromeStore() Store {
	suggestions := collectNssSuggestions(chromeCert8Locations())
	return nssStore{
		paths: suggestions,
	}
}
