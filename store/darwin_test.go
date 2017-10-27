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

	count := 0

	for _, p := range paths {
		certs, err := readInstalledCerts(p)
		if err != nil {
			t.Errorf("%s - err=%v", p, err)
		}
		count += len(certs)

		if !debug {
			continue
		}

		// Debug info
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
		sort.Strings(out)
		fmt.Printf("%s\n", strings.Join(out, "\n"))
	}

	if count == 0 {
		t.Errorf("Didn't find any certs from all %d paths", len(paths))
	}
}

func TestStoreDarwin__trustSettingsExport(t *testing.T) {
	// there's no need to pass in specific keychain files
	fd, err := trustSettingsExport()
	if err != nil {
		t.Error(err)
	}
	st, err := fd.Stat()
	if err != nil {
		t.Error(err)
	}

	if st.Size() <= 0 {
		t.Errorf("fd.Size()=%d, expected >= 0", st.Size())
	}
	// cleanup
	if err = os.Remove(fd.Name()); err != nil {
		t.Error(err)
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

func TestStoreDarwin__trustItemsContains(t *testing.T) {
	installed, err := readInstalledCerts(systemDirs...)
	if err != nil {
		t.Error(err)
	}
	if len(installed) == 0 {
		t.Errorf("len(installed)=%d", len(installed),)
	}

	// just find a cert in the trust items
	found := false
	for i := range installed {
		if installed[i] == nil {
			continue
		}

		item := trustItemFromCertificate(*installed[i])
		items := trustItems([]trustItem{item})
		found = items.contains(installed[i])
		if found {
			break
		}
	}
	if !found {
		t.Error("no installed cert found in trust items")
	}
}

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
