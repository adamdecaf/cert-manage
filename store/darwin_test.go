// +build darwin

package store

import (
	"crypto/x509"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var (
	debug = strings.Contains(os.Getenv("GODEBUG"), "x509roots=1")
)

// There are various locations for certificates across OSX
// Mostly the Keychain groups the certificates (and trust policies)
// into a few groups
func TestStoreDarwin__locations(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("not on darwin based host")
	}

	// Show the difference between the various keychains
	paths := make([]string, 0)
	paths = append(paths, systemDirs...)

	userDirs, _ := getUserDirs()
	paths = append(paths, userDirs...)

	for _, p := range paths {
		certs, err := readDarwinCerts(p)
		if err != nil {
			t.Errorf("%s - err=%v", p, err)
		}
		fmt.Printf("%d certs from %s\n", len(certs), p)
		out := make([]string, 0)
		for i := range certs {
			if certs[i].Subject.CommonName != "" {
				out = append(out, fmt.Sprintf("  Subject CN=%v", certs[i].Subject.CommonName))
				continue
			}
			if certs[i].Issuer.CommonName != "" {
				out = append(out, fmt.Sprintf("  Issuer CN=%v", certs[i].Issuer.CommonName))
				continue
			}
		}
		if debug {
			sort.Strings(out)
			fmt.Printf("%s\n", strings.Join(out, "\n"))
		}
	}
}

func TestStoreDarwin__test(t *testing.T) {
	t.Skip("skipping sys cert pool init")

	fmt.Println(os.Getenv("CGO_ENABLED"))
	pool, _ := x509.SystemCertPool()
	fmt.Printf("%d trusted", len(pool.Subjects()))
}

// TODO(adam): write up a test that finds what CA google.com is trusted by
// and remove that trust, then verify the conn fails, restore trust and
// verify connection succeeds

// TODO(adam): Upstream fix for actually inspecting trust settings?

func TestStoreDarwin__plistParsing(t *testing.T) {
	f, err := os.Open("../testdata/darwin_plist.xml")
	if err != nil {
		t.Fatal(err)
	}
	pl, err := parsePlist(f)
	if err != nil {
		t.Fatal(err)
	}

	trustItems := pl.convertToTrustItems()
	fmt.Printf("%d trustItems\n", len(trustItems))
	for i := range trustItems {
		fmt.Println(trustItems[i])
	}
}
