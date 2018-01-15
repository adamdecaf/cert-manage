package gen

import (
	"net/url"
)

func FromAllBrowsers() ([]*url.URL, error) {
	u, err := url.Parse("http://apple.com")
	return []*url.URL{u}, err
}

func FromBrowser(name string) ([]*url.URL, error) {
	return nil, nil
}
