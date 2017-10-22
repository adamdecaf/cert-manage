// +build darwin

package store

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"io"
	"io/ioutil"
	"regexp"
	"strings"
	"time"
)

const (
	plistFilePerms = 0644
)

// parsePlist takes a reader of the xml output produced by the darwin
// `/usr/bin/security trust-settings-export`
// cli tool and converts it into a series of structs to then read
//
// After getting a `plist` callers will typically want to convert into
// a []trustItem by calling convertToTrustItems()
func parsePlist(in io.Reader) (plist, error) {
	dec := xml.NewDecoder(in)
	var out plist
	err := dec.Decode(&out)
	return out, err
}

// xml format, this was generated with the package github.com/gnewton/chidley
// but has also been modified by hand:
// 1. don't export struct names
// 2. remove outermost ChiChidleyRoot314159 wrapper as parsing fails with it
// 3. make `date []*date` rather than `date *date`

type plist struct {
	// AttrVersion string `xml:" version,attr"  json:",omitempty"`
	ChiDict *chiDict `xml:"dict,omitempty"`
}

type chiDict struct {
	ChiData    []*chiData  `xml:"data,omitempty"`
	ChiDate    []*chiDate  `xml:"date,omitempty"`
	ChiDict    *chiDict    `xml:"dict,omitempty"`
	ChiInteger *chiInteger `xml:"integer,omitempty"`
	ChiKey     []*chiKey   `xml:"key,omitempty"`
}

type chiKey struct {
	Text string `xml:",chardata"`
}

type chiData struct {
	Text string `xml:",chardata"`
}

type chiDate struct {
	Text string `xml:",chardata"`
}

type chiInteger struct {
	Text bool `xml:",chardata"`
}

func (p plist) convertToTrustItems() trustItems {
	out := make([]trustItem, 0)

	// TODO(adam): Add checks to make sure we're on target, and if not panic

	max := len(p.ChiDict.ChiDict.ChiDict.ChiData)
	for i := 0; i < max; i += 2 {
		item := trustItem{}

		item.sha1Fingerprint = strings.ToLower(p.ChiDict.ChiDict.ChiKey[i/2].Text)

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

	return trustItems(out)
}

// TODO(adam): we probably need to create this manually, encoding/xml isn't
// respecting the ordering
// https://golang.org/pkg/encoding/xml/#pkg-note-BUG
func (p plist) toXmlFile(where string) error {
	bs, err := xml.Marshal(p)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(where, bs, plistFilePerms)
}
