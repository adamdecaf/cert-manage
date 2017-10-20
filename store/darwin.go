// +build darwin

package store

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	// stdpem "encoding/pem"
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

var (
	plistModDateFormat = "2006-01-02T15:04:05Z"
	// plistModDateFormat = time.RFC3339

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

type certificate struct {
	TBSCertificate tbsCertificate
	// SignatureAlgorithm algorithmIdentifier
	// SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Version int `asn1:"optional,explicit,default:0,tag:0"`
	// SerialNumber       asn1.RawValue
	// SignatureAlgorithm algorithmIdentifier
	Issuer rdnSequence
	// Validity           validity
	// Subject            rdnSequence
	// PublicKey          publicKeyInfo
}

type algorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

type rdnSequence []relativeDistinguishedNameSET
type relativeDistinguishedNameSET []attributeTypeAndValue
type attributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

// SEQUENCE(7 elem)
//   SET(1 elem)
//     SEQUENCE(2 elem)
//       OBJECT IDENTIFIER2.5.4.6countryName(X.520 DN component)
//         PrintableStringUS
//   SET(1 elem)
//     SEQUENCE(2 elem)
//       OBJECT IDENTIFIER2.5.4.8stateOrProvinceName(X.520 DN component)
//         UTF8StringIowa
//   SET(1 elem)
//     SEQUENCE(2 elem)
//       OBJECT IDENTIFIER2.5.4.7localityName(X.520 DN component)
//         UTF8StringCedar Falls
//   SET(1 elem)
//     SEQUENCE(2 elem)
//       OBJECT IDENTIFIER2.5.4.10organizationName(X.520 DN component)
//         UTF8StringBanno
//   SET(1 elem)
//     SEQUENCE(2 elem)
//       OBJECT IDENTIFIER2.5.4.11organizationalUnitName(X.520 DN component)
//         UTF8StringSecrets
//   SET(1 elem)
//     SEQUENCE(2 elem)
//       OBJECT IDENTIFIER2.5.4.3commonName(X.520 DN component)
//         UTF8StringBanno CA
//   SET(1 elem)
//     SEQUENCE(2 elem)
//       OBJECT IDENTIFIER1.2.840.113549.1.9.1emailAddress(PKCS #9. Deprecated, use an altName extension instead)
//         IA5Stringnoreply@banno.com

type yo []pkix.AttributeTypeAndValueSET

// type ChiChidleyRoot314159 struct {
// 	ChiPlist *ChiPlist `xml:" plist,omitempty" json:"plist,omitempty"`
// }

type ChiPlist struct {
	AttrVersion string `xml:" version,attr"  json:",omitempty"`
	ChiDict *ChiDict `xml:" dict,omitempty" json:"dict,omitempty"`
}

type ChiDict struct {
	ChiData []*ChiData `xml:" data,omitempty" json:"data,omitempty"`
	ChiDate []*ChiDate `xml:" date,omitempty" json:"date,omitempty"`
	ChiDict *ChiDict `xml:" dict,omitempty" json:"dict,omitempty"`
	ChiInteger *ChiInteger `xml:" integer,omitempty" json:"integer,omitempty"`
	ChiKey []*ChiKey `xml:" key,omitempty" json:"key,omitempty"`
}

type ChiKey struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type ChiData struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type ChiDate struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type ChiInteger struct {
	Text bool `xml:",chardata" json:",omitempty"`
}

func (p ChiPlist) convertToTrustItems() []trustItem {
	out := make([]trustItem, 0)

	// fmt.Printf("%v\n", p.ChiDict)

	// fmt.Println("p.ChiDict.ChiData")
	// for i := range p.ChiDict.ChiData {
	// 	fmt.Println(p.ChiDict.ChiData[i])
	// }

	// TODO(adam): Add checks to make sure we're on target, and if not panic

	// fmt.Println("p.ChiDict.ChiDict.ChiDict.ChiData")
	max := len(p.ChiDict.ChiDict.ChiDict.ChiData)
	for i := 0; i < max; i += 2 {
		item := trustItem{}

		// TODO(adam): rename, sha1Fingerprint
		item.key = strings.ToLower(p.ChiDict.ChiDict.ChiKey[i/2].Text)
		// fmt.Println(item.key)

		// fmt.Println(i)
		// fmt.Println(p.ChiDict.ChiDict.ChiDict.ChiData[i].Text)
		// fmt.Println(p.ChiDict.ChiDict.ChiDict.ChiData[i+1].Text)

		// trim whitespace
		r := regexp.MustCompile(`[^a-zA-Z0-9\+\/=]*`)
		r2 := strings.NewReplacer("\t", "", "\n", "", " ", "", "\r", "")

		s1 := r2.Replace(r.ReplaceAllString(p.ChiDict.ChiDict.ChiDict.ChiData[i].Text, ""))
		s2 := r2.Replace(r.ReplaceAllString(p.ChiDict.ChiDict.ChiDict.ChiData[i+1].Text, ""))

		// fmt.Printf(" %s\n", s1)
		// fmt.Printf(" %s\n", s2)

		bs1, _ := base64.StdEncoding.DecodeString(s1)
		bs2, _ := base64.StdEncoding.DecodeString(s2)

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

		// var serial asn1.RawValue
		// _, err = asn1.Unmarshal(bs2, &serial)
		// if err == nil {
		// 	item.serialNumber = serial.FullBytes
		// }
		item.serialNumber = bs2

		out = append(out, item)
	}

	// for i := range p.ChiPlist {
	// 	item := trustItem{}

	// 	fmt.Println(

	// 	// fmt.Println(p.KeyDictDict[i])
	// 	// fmt.Println(p.Data[i])
	// 	// fmt.Println(p.Data[i+1])

	// 	fmt.Println("\n\n")

	// 	// // fmt.Println(p.Data[i][0])

	// 	// // required
	// 	// // TODO(adam): rename, sha1Fingerprint
	// 	// item.key = strings.ToLower(p.KeyDictDict[i])

	// 	// // b := strings.Replace(p.Data[i][0], " ", "", -1)
	// 	// // fmt.Println(b)
	// 	// // b = strings.TrimSpace(b)

	// 	// // // base64 alphabet, plus pad token
	// 	// // r := regexp.MustCompile(`[^a-zA-Z0-9\+\/=]*`)
	// 	// // b := r.ReplaceAllString(p.Data[i][0], "")
	// 	// // fmt.Println("b: " + b)

	// 	// // bs, err := base64.StdEncoding.DecodeString(b)
	// 	// // // fmt.Println(err)
	// 	// // if err == nil {
	// 	// // 	item.issuerName = strings.TrimSpace(string(bs))
	// 	// // 	fmt.Printf("item.issuerName = '%s'\n", item.issuerName)
	// 	// // }

	// 	// // From https://github.com/DHowett/go-plist/blob/master/xml_parser.go
	// 	// // str := p.whitespaceReplacer.Replace(string(charData))
	// 	// // l := base64.StdEncoding.DecodedLen(len(str))
	// 	// // bytes := make([]uint8, l)
	// 	// // l, err = base64.StdEncoding.Decode(bytes, []byte(str))

	// 	// r := regexp.MustCompile(`[^a-zA-Z0-9\+\/=]*`)
	// 	// r2 := strings.NewReplacer("\t", "", "\n", "", " ", "", "\r", "")
	// 	// str := r2.Replace(r.ReplaceAllString(p.Data[i][0], ""))

	// 	// l := base64.StdEncoding.DecodedLen(len(str))
	// 	// bytes := make([]uint8, l)
	// 	// l, err := base64.StdEncoding.Decode(bytes, []byte(str))

	// 	// // block, bytes := stdpem.Decode(bytes)
	// 	// // fmt.Println(block)
	// 	// // fmt.Println(bytes)

	// 	// // var issuer certificate
	// 	// // var issuer tbsCertificate
	// 	// // var issuer rdnSequence
	// 	// var issuer pkix.RDNSequence // best so far
	// 	// // var issuer yo
	// 	// // var issuer asn1.BitString
	// 	// // var issuer pkix.RelativeDistinguishedNameSET
	// 	// // _, err = asn1.Unmarshal(bytes, &issuer)
	// 	// _, err = asn1.UnmarshalWithParams(bytes, &issuer, "optional")
	// 	// // fmt.Println(string(other))
	// 	// // fmt.Println(string(final.Bytes))
	// 	// // fmt.Println(err)

	// 	// if err != nil {
	// 	// 	// asn1: structure error: tags don't match (16 vs {class:0 tag:1 length:0 isCompound:false})
	// 	// 	// {optional:false explicit:false application:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} rdnSequence @2
	// 	// 	fmt.Println(err)
	// 	// }

	// 	// if err == nil {
	// 	// 	name := pkix.Name{}
	// 	// 	name.FillFromRDNSequence(&issuer)
	// 	// 	// fmt.Printf("key=%s, issuer=%v\n", item.key, name)
	// 	// 	// fmt.Printf("key=%s, issuer=%s\n", item.key, issuer)

	// 	// 	item.issuerName = name
	// 	// 	// item.issuerName = string(final)
	// 	// 	// item.issuerName = string(final.Bytes)
	// 	// 	// fmt.Printf("item.issuerName = '%s'\n", item.issuerName)
	// 	// }

	// 	// t, err := time.ParseInLocation(time.RFC3339, string(p.Date[i]), time.UTC)
	// 	// if err == nil {
	// 	// 	item.modDate = t
	// 	// }

	// 	// // serial number
	// 	// str = r2.Replace(r.ReplaceAllString(p.Data[i+1][0], ""))
	// 	// fmt.Println(str)
	// 	// bs, err := base64.StdEncoding.DecodeString(str)
	// 	// if err == nil {
	// 	// 	// var serial asn1.RawValue
	// 	// 	// _, err := asn1.Unmarshal(bs, &serial)
	// 	// 	// if err == nil {
	// 	// 	// 	item.serialNumber = serial.FullBytes
	// 	// 	// }
	// 	// 	item.serialNumber = bs
	// 	// }

	// 	// // i += 1 ??

	// 	out = append(out, item)
	// }

	return out
}

func parsePlist(in io.Reader) (ChiPlist, error) {
	dec := xml.NewDecoder(in)
	// var out ChiChidleyRoot314159
	var out ChiPlist
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

func (t trustItem) String() string {
	serial := big.NewInt(0)
	serial.SetBytes(t.serialNumber)

	modDate := t.modDate.Format(plistModDateFormat)

	name := fmt.Sprintf("O=%s", strings.Join(t.issuerName.Organization, " "))
	if t.issuerName.CommonName != "" {
		name = fmt.Sprintf("CN=%s", t.issuerName.CommonName)
	}

	country := strings.Join(t.issuerName.Country, " ")

	return fmt.Sprintf("SHA1 Fingerprint: %s\n %s (%s)\n modDate: %s\n serialNumber: %d", t.key, name, country, modDate, serial)
}
