package gen

import (
	"net/url"
)

// TODO(adam): impl
func FromAllBrowsers() ([]*url.URL, error) {
	u, err := url.Parse("http://apple.com")
	return []*url.URL{u}, err
}

// TODO(adam): impl
func FromBrowser(name string) ([]*url.URL, error) {
	return nil, nil
}
