package cmd

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/store"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
	"github.com/adamdecaf/cert-manage/pkg/whitelist/gen"
)

var (
	debug = os.Getenv("DEBUG") != ""

	exampleDNSNamesLength = 3
)

func GenerateWhitelist(output string, from, file string) error {
	if output == "" || (from == "" && file == "") {
		return errors.New("you need to specify -out <path> and either -from or -file")
	}
	output, err := filepath.Abs(output)
	if err != nil {
		return err
	}

	var accum []*url.URL
	var mu sync.Mutex
	uacc := make(chan []*url.URL)
	eacc := make(chan error)

	pool := x509.NewCertPool()

	choices := getChoices(from, file)
	debugLog("running %d choices\n", len(choices))
	for i := range choices {
		opt := strings.ToLower(strings.TrimSpace(choices[i]))
		switch opt {
		case "browser", "browsers":
			debugLog("starting browser url retrieval")
			go accumulateUrls(gen.FromAllBrowsers, uacc, eacc)
			addCertsToPool(pool, gen.BrowserCAs)

		case "file":
			debugLog("grabbing urls from %s", file)
			go accumulateUrls(func() ([]*url.URL, error) {
				return gen.FromFile(file)
			}, uacc, eacc)
			addCertsToPool(pool, store.Platform().List)

		default:
			debugLog("starting %s url retrieval", opt)
			go accumulateUrls(func() ([]*url.URL, error) {
				return gen.FromBrowser(opt)
			}, uacc, eacc)
			addCertsToPoolForApp(pool, opt)
		}
	}

	for range choices {
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
	debugLog("cleaning up from url retrieval")
	close(uacc)
	close(eacc)

	if debug {
		fmt.Printf("getting chains for %d urls\n", len(accum))
	}

	// Generate whitelist and write to file
	authorities, err := gen.FindCAs(accum, pool)
	if err != nil {
		return err
	}

	// prep summary
	sortCAs(authorities)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "CA\tFingerprint\tCount\tExample DNSNames")

	var acc []*x509.Certificate
	for i := range authorities {
		acc = append(acc, authorities[i].Certificate)

		// print sumamry
		dnsNames := authorities[i].DNSNames
		if len(dnsNames) > exampleDNSNamesLength {
			dnsNames = authorities[i].DNSNames[:exampleDNSNamesLength]
		}

		row := fmt.Sprintf("%s\t%s\t%d\t%s",
			certutil.StringifyPKIXName(authorities[i].Certificate.Issuer),
			authorities[i].Fingerprint[:16],
			len(authorities[i].DNSNames),
			strings.Join(dnsNames, ", "),
		)
		fmt.Fprintln(w, row)
	}
	w.Flush()

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

func addCertsToPool(pool *x509.CertPool, f func() ([]*x509.Certificate, error)) {
	certs, err := f()
	if err == nil {
		for i := range certs {
			pool.AddCert(certs[i])
		}
	}
}

func addCertsToPoolForApp(pool *x509.CertPool, appName string) {
	st, err := store.ForApp(appName)
	if err != nil {
		st = store.Platform() // try and give something as a root store
	}
	addCertsToPool(pool, st.List)
}

func debugLog(msg string, args ...interface{}) {
	if debug {
		fmt.Printf("cmd/gen-whitelist: "+msg+"\n", args...)
	}
}

// sortableCAs defines a sorting order on gen.CA by len(CA.DNSNames) in descending order
type sortableCAs []*gen.CA

func (c sortableCAs) Len() int {
	return len(c)
}
func (c sortableCAs) Less(i, j int) bool {
	return len(c[i].DNSNames) > len(c[j].DNSNames)
}
func (c sortableCAs) Swap(i, j int) {
	c[i].DNSNames, c[j].DNSNames = c[j].DNSNames, c[i].DNSNames
}
func sortCAs(c []*gen.CA) {
	sort.Sort(sortableCAs(c))
}
