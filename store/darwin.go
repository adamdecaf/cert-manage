// +build darwin

package store

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"time"
	"strings"
	"regexp"

	"github.com/adamdecaf/cert-manage/tools/pem"
	"github.com/adamdecaf/cert-manage/whitelist"
)

// Docs
// - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html

var (
	plistModDateFormat = "2006-01-02T15:04:05Z"

	systemDirs = []string{
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

// TODO(adam): parse xml from trust-settings-export
// Docs: https://developer.apple.com/documentation/security/certificate_key_and_trust_services/trust/usage_constraints_dictionary_keys?language=objc
//
// My export has these a few times
// <key>kSecTrustSettingsResult</key> and <integer>3</integer>
// <key>kSecTrustSettingsResult</key> and <integer>4</integer>

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

// Parse and Generate plists from apple
// Generated with: https://github.com/wicast/xj2s
type plist struct {
	// Key                      []string   `xml:"dict>key"`
	KeyDictDict              []string   `xml:"dict>dict>key"`
	KeyDictDictDict          [][]string `xml:"dict>dict>dict>key"`
	Data                     [][]string `xml:"dict>dict>dict>data"`
	Date                     []string   `xml:"dict>dict>dict>date"`
	KeyDictArrayDictDictDict []string   `xml:"dict>dict>dict>array>dict>key"`
	Integer                  []string   `xml:"dict>dict>dict>array>dict>integer"`
	IntegerDict              string     `xml:"dict>integer"`
	Version                  string     `xml:"version,attr"`
}

func (p plist) convertToTrustItems() []trustItem {
	out := make([]trustItem, 0)

	for i := range p.KeyDictDict {
		item := trustItem{}

		// fmt.Println(p.Data[i][0])

		// required
		// TODO(adam): rename, sha1Fingerprint
		item.key = strings.ToLower(p.KeyDictDict[i])

		// b := strings.Replace(p.Data[i][0], " ", "", -1)
		// fmt.Println(b)
		// b = strings.TrimSpace(b)


		// // base64 alphabet, plus pad token
		// r := regexp.MustCompile(`[^a-zA-Z0-9\+\/=]*`)
		// b := r.ReplaceAllString(p.Data[i][0], "")
		// fmt.Println("b: " + b)

		// bs, err := base64.StdEncoding.DecodeString(b)
		// // fmt.Println(err)
		// if err == nil {
		// 	item.issuerName = strings.TrimSpace(string(bs))
		// 	fmt.Printf("item.issuerName = '%s'\n", item.issuerName)
		// }

		// From https://github.com/DHowett/go-plist/blob/master/xml_parser.go
		// str := p.whitespaceReplacer.Replace(string(charData))
		// l := base64.StdEncoding.DecodedLen(len(str))
		// bytes := make([]uint8, l)
		// l, err = base64.StdEncoding.Decode(bytes, []byte(str))

		r := regexp.MustCompile(`[^a-zA-Z0-9\+\/=]*`)
		r2 := strings.NewReplacer("\t", "", "\n", "", " ", "", "\r", "")
		str := r2.Replace(r.ReplaceAllString(p.Data[i][0], ""))

		l := base64.StdEncoding.DecodedLen(len(str))
		bytes := make([]uint8, l)
		l, err := base64.StdEncoding.Decode(bytes, []byte(str))

		var final asn1.RawValue
		_, err = asn1.Unmarshal(bytes, &final)
		// fmt.Println(string(other))
		// fmt.Println(string(final.Bytes))
		// fmt.Println(err)

		if err == nil {
			// item.issuerName = string(final)

			item.issuerName = string(final.Bytes)
			// fmt.Printf("item.issuerName = '%s'\n", item.issuerName)
		}

		t, err := time.ParseInLocation(time.RFC3339, string(p.Date[i]), time.UTC)
		if err == nil {
			item.modDate = t
		}

		bs, err := base64.StdEncoding.DecodeString(p.Data[i+1][0])
		if err == nil {
			item.serialNumber = bs
		}

		// TODO(adam): optional

		out = append(out, item)
	}

	return out
}

func parsePlist(in io.Reader) (plist, error) {
	var out plist
	dec := xml.NewDecoder(in)
	err := dec.Decode(&out)
	return out, err
}

// The human readable struct
type trustItem struct {
	// required
	key string
	issuerName string
	modDate time.Time
	serialNumber []byte

	// optional
	kSecTrustSettingsResult int32
}

func (t trustItem) String() string {
	return fmt.Sprintf("sha1Fingerprint:%s, issuerName:%s, modDate: %s",
		t.key, t.issuerName, t.modDate.Format(plistModDateFormat))
}
