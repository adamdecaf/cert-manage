package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/adamdecaf/cert-manage/pkg/whitelist/gen"
)

var (
	debug = os.Getenv("DEBUG") != ""
)

func GenerateWhitelist(from, file string) error {
	if from == "" && file == "" {
		return errors.New("you need to specify either -from or -file")
	}

	var accum []*url.URL
	var err error
	var mu sync.Mutex
	uacc := make(chan []*url.URL)
	eacc := make(chan error)

	choices := getChoices(from, file)
	debugLog("running %d choices\n", len(choices))
	for i := range choices {
		opt := strings.ToLower(strings.TrimSpace(choices[i]))
		switch opt {
		case "browser", "browsers":
			debugLog("starting browser url retrieval")
			go accumulateUrls(gen.FromAllBrowsers, uacc, eacc)

		case "chrome", "edge", "firefox", "ie", "opera", "safari":
			debugLog("starting %s url retrieval", opt)
			go accumulateUrls(func() ([]*url.URL, error) {
				return gen.FromBrowser(opt)
			}, uacc, eacc)
		case "file":
			debugLog("grabbing urls from %s", file)
			go accumulateUrls(func() ([]*url.URL, error) {
				return gen.FromFile(file)
			}, uacc, eacc)
		default:
			fmt.Printf("WARNING: Unknown -from option %q\n", opt)
		}
	}

	for _ = range choices {
		select {
		case urls := <-uacc:
			mu.Lock()
			debugLog("accumulating %d urls", len(urls))
			accum = append(accum, urls...)
			mu.Unlock()
		case err1 := <-eacc:
			mu.Lock()
			if err1 != nil {
				err = err1
			}
			mu.Unlock()
		}
	}
	debugLog("cleaning up")
	close(uacc)
	close(eacc)
	fmt.Printf("out=%q\n", accum)

	// TODO(adam): capture CA's from urls
	// then create whitelist
	// and whitelist.ToFile(path, wh)

	return err
}

func getChoices(from, file string) []string {
	if !strings.Contains(from, "file") && file != "" {
		if from != "" {
			from += ","
		}
		from += "file"
	}
	return strings.Split(from, ",")
}

func accumulateUrls(f func() ([]*url.URL, error), u chan []*url.URL, e chan error) {
	urls, err := f() // often long blocking call
	if err != nil {
		e <- err
	} else {
		debugLog("adding %d urls", len(urls))
		u <- urls
	}
}

func debugLog(msg string, args ...interface{}) {
	if debug {
		fmt.Printf("cmd/gen-whitelist: "+msg+"\n", args...)
	}
}
