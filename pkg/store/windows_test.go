// +build windows

package store

import (
	"reflect"
	"testing"
)

func TestStoreWindows__certSerialsFromStore(t *testing.T) {
	win := windowsStore{}

	in := `Root "Trusted Root Certification Authorities"
================ Certificate 0 ================
Serial Number: 72696afcd5edce864658141cb588a3a8
Issuer: CN=WinDev1712Eval
 NotBefore: 12/3/2017 9:55 PM
 NotAfter: 4/5/3017 9:55 PM
Subject: CN=WinDev1712Eval
Signature matches Public Key
Root Certificate: Subject matches Issuer
Cert Hash(sha1): ef56cf1f0052b3ff7a1c834cfa3d71ea0d72c04e
  Key Container = a3815d1a-0473-4a96-9375-cf18cc03b2f5
  Provider = Microsoft RSA SChannel Cryptographic Provider
Missing stored keyset

Root "other"
================ Certificate 0 ================
Serial Number: 214817429841748bbbcccca`
	serials, err := win.readCertSerials(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(serials) != 2 {
		t.Errorf("got %d serials", len(serials))
	}
	ans := []string{
		"72696afcd5edce864658141cb588a3a8",
		"214817429841748bbbcccca",
	}
	if !reflect.DeepEqual(serials, ans) {
		t.Errorf("got %q", serials)
	}
}

func TestStoreWindows__getInfo(t *testing.T) {
	info := Platform().GetInfo()
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
