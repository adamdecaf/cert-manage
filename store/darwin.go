// +build darwin

package store

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/adamdecaf/cert-manage/tools/pem"
	"github.com/adamdecaf/cert-manage/whitelist"
)

// Docs
// - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html
// - https://github.com/adamdecaf/cert-manage/issues/9#issuecomment-337778241

var (
	plistModDateFormat = "2006-01-02T15:04:05Z"
	systemDirs         = []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}
)

func getUserDirs() ([]string, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	return []string{
		filepath.Join(u.HomeDir, "/Library/Keychains/login.keychain"),
		filepath.Join(u.HomeDir, "/Library/Keychains/login.keychain-db"),
	}, nil
}

type darwinStore struct{}

func platform() Store {
	return darwinStore{}
}

func (s darwinStore) Backup() error {
	return nil
}

// List
//
// Note: Currently we are ignoring the login keychain. This is done because those certs are
// typically modified by the user (or an application the user trusts).
func (s darwinStore) List() ([]*x509.Certificate, error) {
	// TODO(adam): Should we call `x509.SystemCertPool()` instead?
	// We need to apply the trust settings anyway..
	return readDarwinCerts(systemDirs...)
}

func readDarwinCerts(paths ...string) ([]*x509.Certificate, error) {
	res := make([]*x509.Certificate, 0)

	args := []string{"find-certificate", "-a", "-p"}
	args = append(args, paths...)

	b, err := exec.Command("/usr/bin/security", args...).Output()
	if err != nil {
		return nil, err
	}

	cs, err := pem.Parse(b)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c == nil {
			continue
		}
		add := true
		for i := range res {
			if reflect.DeepEqual(c.Signature, res[i].Signature) {
				add = false
				break
			}
		}
		if add {
			res = append(res, c)
		}
	}

	return res, nil
}

// TODO(adam): impl
func (s darwinStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s darwinStore) Restore() error {
	// /usr/bin/security trust-settings-import
	// ^ will prompt users, so I think the 'Restore' should just be
	// outputting what command to run and telling users to run it
	return nil
}

// security remove-trusted-cert <crt-file>
// What does ^ do, exactly?
// How does restore look?

// /usr/bin/security trust-settings-export
// /usr/bin/security trust-settings-import
// Could this be used in as a big batch operation?

// Is there a way to disable a cert? aka mark it as "Never Trust"?
// Otherwise, we'll need to make a full backup of all certs before touching anything.

// xml format, this was generated with the package github.com/gnewton/chidley
// but has also been modified by hand:
// 1. don't export struct names
// 2. remove outermost ChiChidleyRoot314159 wrapper as parsing fails with it
// 3. make `date []*date` rather than `date *date`

type chiPlist struct {
	// AttrVersion string `xml:" version,attr"  json:",omitempty"`
	ChiDict *chiDict `xml:" dict,omitempty" json:"dict,omitempty"`
}

type chiDict struct {
	ChiData    []*chiData  `xml:" data,omitempty" json:"data,omitempty"`
	ChiDate    []*chiDate  `xml:" date,omitempty" json:"date,omitempty"`
	ChiDict    *chiDict    `xml:" dict,omitempty" json:"dict,omitempty"`
	ChiInteger *chiInteger `xml:" integer,omitempty" json:"integer,omitempty"`
	ChiKey     []*chiKey   `xml:" key,omitempty" json:"key,omitempty"`
}

type chiKey struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type chiData struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type chiDate struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type chiInteger struct {
	Text bool `xml:",chardata" json:",omitempty"`
}

func (p chiPlist) convertToTrustItems() []trustItem {
	out := make([]trustItem, 0)

	// TODO(adam): Add checks to make sure we're on target, and if not panic

	max := len(p.ChiDict.ChiDict.ChiDict.ChiData)
	for i := 0; i < max; i += 2 {
		item := trustItem{}

		// TODO(adam): rename, sha1Fingerprint
		item.key = strings.ToLower(p.ChiDict.ChiDict.ChiKey[i/2].Text)

		// trim whitespace
		r := regexp.MustCompile(`[^a-zA-Z0-9\+\/=]*`)
		r2 := strings.NewReplacer("\t", "", "\n", "", " ", "", "\r", "")

		s1 := r2.Replace(r.ReplaceAllString(p.ChiDict.ChiDict.ChiDict.ChiData[i].Text, ""))
		s2 := r2.Replace(r.ReplaceAllString(p.ChiDict.ChiDict.ChiDict.ChiData[i+1].Text, ""))

		bs1, _ := base64.StdEncoding.DecodeString(s1)
		bs2, _ := base64.StdEncoding.DecodeString(s2)

		// The issuerName's <data></data> block is only under asn1 encoding for the
		// issuerName field from 4.1.2.4 (https://tools.ietf.org/rfc/rfc5280)
		var issuer pkix.RDNSequence
		_, err := asn1.Unmarshal(bs1, &issuer)
		if err == nil {
			name := pkix.Name{}
			name.FillFromRDNSequence(&issuer)
			item.issuerName = name
		}

		dt := p.ChiDict.ChiDict.ChiDict.ChiDate[i/2].Text
		t, err := time.ParseInLocation(plistModDateFormat, dt, time.UTC)
		if err == nil {
			item.modDate = t
		}

		// serialNumber is just a base64 encoded big endian (big) int
		item.serialNumber = bs2

		out = append(out, item)
	}

	return out
}

func parsePlist(in io.Reader) (chiPlist, error) {
	dec := xml.NewDecoder(in)
	var out chiPlist
	err := dec.Decode(&out)
	return out, err
}

// The human readable struct
type trustItem struct {
	// required
	key          string
	issuerName   pkix.Name
	modDate      time.Time
	serialNumber []byte

	// optional
	kSecTrustSettingsResult int32
}

func (t trustItem) Serial() *big.Int {
	serial := big.NewInt(0)
	serial.SetBytes(t.serialNumber)
	return serial
}

func (t trustItem) String() string {
	modDate := t.modDate.Format(plistModDateFormat)

	name := fmt.Sprintf("O=%s", strings.Join(t.issuerName.Organization, " "))
	if t.issuerName.CommonName != "" {
		name = fmt.Sprintf("CN=%s", t.issuerName.CommonName)
	}

	country := strings.Join(t.issuerName.Country, " ")

	return fmt.Sprintf("SHA1 Fingerprint: %s\n %s (%s)\n modDate: %s\n serialNumber: %d", t.key, name, country, modDate, t.Serial())
}
