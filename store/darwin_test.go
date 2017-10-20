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
		if debug {
			fmt.Printf("%d certs from %s\n", len(certs), p)
		}
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
	if len(trustItems) != 4 {
		t.Fatalf("got %d trust items parsed", len(trustItems))
	}

	compare := func(answer string, item trustItem, t *testing.T) {
		if item.String() != answer {
			t.Errorf("%d didn't match", item.Serial())
		}
	}

	compare(`SHA1 Fingerprint: 02faf3e291435468607857694df5e45b68851868
 CN=AddTrust External CA Root (SE)
 modDate: 2015-12-05T01:31:11Z
 serialNumber: 1`, trustItems[0], t)

	compare(`SHA1 Fingerprint: 039eedb80be7a03c6953893b20d2d9323a4c2afd
 CN=GeoTrust Primary Certification Authority - G3 (US)
 modDate: 2015-12-05T01:31:24Z
 serialNumber: 28809105769928564313984085209975885599`, trustItems[1], t)

	compare(`SHA1 Fingerprint: feb8c432dcf9769aceae3dd8908ffd288665647d
 O=SECOM Trust Systems CO.,LTD. (JP)
 modDate: 2015-12-05T01:31:30Z
 serialNumber: 0`, trustItems[2], t)

	compare(`SHA1 Fingerprint: ffad0e26f05bbcd8063cce1dfa60245e143d5380
 CN=DigiNotar Root CA (NL)
 modDate: 2015-12-05T01:31:48Z
 serialNumber: 122067666349187366727678587394970725697`, trustItems[3], t)
}
