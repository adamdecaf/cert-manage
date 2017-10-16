// +build darwin

package store

import (
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
