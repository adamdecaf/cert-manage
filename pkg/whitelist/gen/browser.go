package gen

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/adamdecaf/cert-manage/pkg/store"
)

type getter func() ([]*url.URL, error)

var (
	browserGetters = []getter{
		chrome,
		firefox,
	}

	// requires updating with store/store.go, but so does the
	// rest of this file
	browserNames = []string{"chrome", "firefox"}
)

func FromAllBrowsers() ([]*url.URL, error) {
	var acc []*url.URL
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	wg.Add(len(browserGetters))

	for i := range browserGetters {
		go func(i int) {
			urls, _ := browserGetters[i]()
			mu.Lock()
			acc = append(acc, urls...)
			mu.Unlock()
			wg.Done()
		}(i)
	}

	wg.Wait()

	if len(acc) == 0 {
		return acc, errors.New("no browser history found")
	}
	return acc, nil
}

func BrowserCAs() ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for i := range browserNames {
		st, err := store.ForApp(browserNames[i])
		if err != nil {
			fmt.Printf("WARNING: error getting hard-coded browser %s, err=%v\n", browserNames[i], err)
		}
		certs, err := st.List()
		if err == nil {
			out = append(out, certs...)
		}
	}
	return out, nil
}

func FromBrowser(name string) ([]*url.URL, error) {
	switch strings.ToLower(name) {
	case "firefox":
		return firefox()
	case "chrome":
		return chrome()
	}
	return nil, nil
}
