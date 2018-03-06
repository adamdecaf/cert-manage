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

	// requires updating with store/store.go, but so does the
	// rest of this file
	browserNames = []string{"chrome", "firefox", "safari"}
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

func FromBrowser(name string) ([]*url.URL, error) {
	switch strings.ToLower(name) {
	case "chrome":
		return chrome()
	case "firefox":
		return firefox()
	case "safari":
		return safari()
	}
	return nil, nil
}
