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

package gen

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/store"
)

type getter func() ([]*url.URL, error)

var (
	browserGetters = []getter{
		chrome,
		firefox,
		safari,
	}
	browserNames = []string{"chrome", "firefox", "safari"}

	// Don't collect history items older than this threshold
	oldestBrowserHistoryItemDate time.Time
)

func init() {
	t, err := time.ParseDuration(fmt.Sprintf("-%dh", 90*24)) // 90 days * 24 hours
	if err != nil {
		panic(err)
	}
	oldestBrowserHistoryItemDate = time.Now().Add(t)
}

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
	return distinct(acc), nil
}

func BrowserCAs() ([]*x509.Certificate, error) {
	pool := certutil.Pool{}
	for i := range browserNames {
		st, err := store.ForApp(browserNames[i])
		if err != nil {
			fmt.Printf("WARNING: error getting hard-coded browser %s, err=%v\n", browserNames[i], err)
		}
		certs, err := st.List(&store.ListOptions{
			Trusted: true,
		})
		if err == nil {
			pool.AddCertificates(certs)
		}
	}
	return pool.GetCertificates(), nil
}

func FromBrowser(name string) (urls []*url.URL, err error) {
	switch strings.ToLower(name) {
	case "chrome":
		urls, err = chrome()
	case "firefox":
		urls, err = firefox()
	case "safari":
		urls, err = safari()
	}
	return distinct(urls), err
}

// distinct returns an array with each url included only once
// URL fragments are removed
func distinct(urls []*url.URL) []*url.URL {
	if len(urls) == 0 {
		return nil
	}

	out := make(map[string]*url.URL, 0)

	// add each url (key: url.URL.Host, value: *url.URL)
	for i := range urls {
		urls[i].Fragment = "" // drop fragment
		if _, exists := out[urls[i].Host]; !exists {
			out[urls[i].Host] = urls[i]
		}
	}

	// Build result from `out`
	var results []*url.URL
	for _, u := range out {
		results = append(results, u)
	}
	return results
}
