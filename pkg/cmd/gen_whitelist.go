package cmd

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/adamdecaf/cert-manage/pkg/whitelist"
	"github.com/adamdecaf/cert-manage/pkg/whitelist/gen"
)

var (
	debug = os.Getenv("DEBUG") != ""
)

func GenerateWhitelist(output string, from, file string) error {
	if from == "" && file == "" {
		return errors.New("you need to specify either -from or -file")
	}
	if output == "" {
		return errors.New("you need to specify -out <path>")
	}
	output, err := filepath.Abs(output)
	if err != nil {
		return err
	}

	var accum []*url.URL
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
		case err := <-eacc:
			return err
		}
	}
	debugLog("cleaning up")
	close(uacc)
	close(eacc)

	// Generate whitelist and write to file
	certs, err := gen.FindCACertificates(accum)
	if err != nil {
		return err
	}
	var acc []*x509.Certificate
	for i := range certs {
		acc = append(acc, certs[i].Certificate)
	}
	wh := whitelist.FromCertificates(acc)
	return wh.ToFile(output)
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
