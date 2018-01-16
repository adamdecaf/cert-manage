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
