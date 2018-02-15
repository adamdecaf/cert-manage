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

package cmd

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestGenWhitelist_getChoices(t *testing.T) {
	// left off '-from file'
	choices := getChoices("", "/dev/null")
	if !reflect.DeepEqual(choices, []string{"file"}) {
		t.Errorf("got %q", choices)
	}

	// has '-from file'
	choices = getChoices("file", "/dev/null")
	if !reflect.DeepEqual(choices, []string{"file"}) {
		t.Errorf("got %q", choices)
	}

	// browser
	choices = getChoices("browser", "")
	if !reflect.DeepEqual(choices, []string{"browser"}) {
		t.Errorf("got %q", choices)
	}

	// comma separated list
	choices = getChoices("browser,file", "")
	if !reflect.DeepEqual(choices, []string{"browser", "file"}) {
		t.Errorf("got %q", choices)
	}
}

func TestGenWhitelist_accumulateUrls(t *testing.T) {
	uacc := make(chan []*url.URL)
	eacc := make(chan error)
	wg := sync.WaitGroup{}

	// happy path
	fn := func() ([]*url.URL, error) {
		defer wg.Done()
		u, _ := url.Parse("https://github.com")
		return []*url.URL{u}, nil
	}
	wg.Add(1)
	go accumulateUrls(fn, uacc, eacc)
	wg.Wait() // just so we ensure the code finished

	select {
	case urls := <-uacc:
		if len(urls) != 1 {
			t.Errorf("got %q", urls)
		}
	case err := <-eacc:
		t.Error(err)
	}

	// unhappy path
	fn = func() ([]*url.URL, error) {
		defer wg.Done()
		return nil, errors.New("whoops")
	}
	wg.Add(1)
	go accumulateUrls(fn, uacc, eacc)
	wg.Wait() // just so we ensure the code finished

	select {
	case urls := <-uacc:
		t.Errorf("expected error, got %q", urls)
	case err := <-eacc:
		if !strings.Contains(err.Error(), "whoops") {
			t.Errorf("got %q", err)
		}
	}
}
