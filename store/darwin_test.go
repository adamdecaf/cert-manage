// +build darwin

package store

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/adamdecaf/cert-manage/tools/file"
)

func TestStoreDarwin__Backup(t *testing.T) {
	dir, err := getCertManageDir()
	if err != nil {
		t.Error(err)
	}
	namesBefore, err := ioutil.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Error(err)
	}

	s := platform()
	err = s.Backup()
	if err != nil {
		t.Error(err)
	}

	// check we added one backup file
	namesAfter, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Error(err)
	}
	if len(namesAfter)-len(namesBefore) != 1 {
		t.Errorf("before=%d, after=%d", len(namesBefore), len(namesAfter))
	}

	// make sure backup file is non-empty
	latest, err := getLatestBackupFile()
	defer os.Remove(latest)
	if err != nil {
		t.Error(err)
	}

	fi, err := os.Stat(latest)
	if err != nil {
		t.Error(err)
	}
	if fi.Size() == 0 {
		t.Errorf("backup file %s is empty", latest)
	}
}

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
		certs, err := readInstalledCerts(p)
		if err != nil {
			t.Errorf("%s - err=%v", p, err)
		}
		if len(certs) == 0 && file.Exists(p) {
			t.Error("didn't find any certs")
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

func TestStoreDarwin__trust(t *testing.T) {
	withPolicy, err := getCertsWithTrustPolicy()
	if err != nil {
		t.Error(err)
	}
	if len(withPolicy) == 0 {
		t.Error("didn't find any trust policies")
	}
}
