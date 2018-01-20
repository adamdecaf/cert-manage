package gen

import (
	"errors"
	"net/url"
	"strings"
	"sync"
)

type getter func() ([]*url.URL, error)

func FromAllBrowsers() ([]*url.URL, error) {
	gets := []getter{
		chrome,
		firefox,
	}

	var acc []*url.URL
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	wg.Add(len(gets))

	for i := range gets {
		go func(i int) {
			urls, _ := gets[i]()
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

func FromBrowser(name string) ([]*url.URL, error) {
	switch strings.ToLower(name) {
	case "firefox":
		return firefox()
	case "chrome":
		return chrome()
	}
	return nil, nil
}
