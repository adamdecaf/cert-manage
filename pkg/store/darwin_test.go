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

// +build darwin

package store

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestStoreDarwin__SystemCertPool(t *testing.T) {
	if !debug {
		t.Skip("skipping SystemCertPool() test")
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%d from Go's SystemCertPool()\n", len(pool.Subjects()))
}

func TestStoreDarwin__Backup(t *testing.T) {
	t.Skip("darwin support is wip")

	dir, err := getCertManageDir(darwinBackupDir)
	if err != nil {
		t.Fatal(err)
	}
	namesBefore, err := ioutil.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	s := platform()
	err = s.Backup()
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	// check we added one backup file
	namesAfter, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(namesAfter)-len(namesBefore) != 1 {
		t.Errorf("before=%d, after=%d", len(namesBefore), len(namesAfter))
	}

	// make sure backup file is non-empty
	latest, err := getLatestBackup(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(latest)

	fi, err := os.Stat(latest)
	if err != nil {
		t.Fatal(err)
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
	paths, err := getKeychainPaths(systemKeychains)
	if err != nil {
		t.Fatal(err)
	}

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
	t.Skip("darwin support is wip")

	// there's no need to pass in specific keychain files
	fd, err := trustSettingsExport()
	if err != nil {
		t.Fatal(err)
	}
	st, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
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
	t.Skip("darwin support is wip")

	withPolicy, err := getCertsWithTrustPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(withPolicy) == 0 {
		t.Error("didn't find any trust policies")
	}
}

func TestStoreDarwin__trustItemsContains(t *testing.T) {
	installed, err := readInstalledCerts(systemKeychains...)
	if err != nil {
		t.Fatal(err)
	}
	if len(installed) == 0 {
		t.Errorf("len(installed)=%d", len(installed))
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
	f, err := os.Open("../../testdata/darwin_plist.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pl, err := parsePlist(f)
	if err != nil {
		t.Fatal(err)
	}

	trustItems := pl.convertToTrustItems()
	if len(trustItems) != 5 {
		t.Errorf("got %d trust items parsed", len(trustItems))
	}

	compare := func(answer string, item trustItem, t *testing.T) {
		if item.String() != answer {
			t.Errorf("%d didn't match\n%s", item.Serial(), item.String())
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

	compare(`SHA1 Fingerprint: ccab0ea04c2301d6697bdd379fcd12eb24e3949d
 CN=AddTrust Class 1 CA Root (SE)
 modDate: 2017-10-27T15:10:39Z
 serialNumber: 1`, trustItems[4], t)
}

func TestStoreDarwin__plistGeneration(t *testing.T) {
	// read, parse and generate an identical plist file
	f1, err := os.Open("../../testdata/darwin_plist.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()
	pl1, err := parsePlist(f1)
	if err != nil {
		t.Fatal(err)
	}
	t1 := pl1.convertToTrustItems()

	// generate the list back
	tmp, err := ioutil.TempFile("", "plist-gen-cycle")
	if err != nil {
		t.Fatal(err)
	}
	err = t1.toXmlFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	// load the generated xml
	f2, err := os.Open(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	pl2, err := parsePlist(f2)
	if err != nil {
		t.Fatal(err)
	}
	t2 := pl2.convertToTrustItems()

	// compare
	if len(t1) != len(t2) {
		t.Fatalf("len(t1)=%d, len(t2)=%d, t2=%s", len(t1), len(t2), tmp.Name())
	}
	// assume ordering is consistent
	for i := range t1 {
		if !t1[i].equal(t2[i]) {
			t.Fatalf("t1[%d] != t2[%d]\n%s\n\n%s\n", i, i, t1[i].String(), t2[i].String())
		}
	}

	// cleanup
	os.Remove(tmp.Name())
}

func TestStoreDarwin__nilplist(t *testing.T) {
	var pl plist
	if l := len(pl.convertToTrustItems()); l != 0 {
		t.Errorf("somehow got %d items from nil plist", l)
	}
}

func TestStoreDarwin__info(t *testing.T) {
	st := darwinStore{}
	info := st.GetInfo()
	if info == nil {
		t.Fatal("nil Info")
	}
	if info.Name == "" {
		t.Error("blank Name")
	}
	if info.Version == "" {
		t.Error("blank Version")
	}
}
