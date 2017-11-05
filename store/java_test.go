package store

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreJava__getKeystorePath(t *testing.T) {
	// Create a fake cacerts file
	dir, err := ioutil.TempDir("", "cert-manage-java")
	if err != nil {
		t.Error(err)
	}
	kpath := filepath.Join(dir, "cacerts")
	err = ioutil.WriteFile(kpath, []byte("A"), 0666)
	if err != nil {
		t.Error(err)
	}

	// Now try and find it
	kt1 := keytool{
		javahome:              dir,
		javaInstallPaths:      nil,
		relativeKeystorePaths: []string{"cacerts"},
	}
	kp1, err := kt1.getKeystorePath()
	if err != nil {
		t.Error(err)
	}
	if kp1 != kpath {
		t.Errorf("kp1=%s != kpath=%s", kp1, kpath)
	}

	// Find without JAVA_HOMe
	kt2 := keytool{
		javahome:              "",
		javaInstallPaths:      []string{dir},
		relativeKeystorePaths: []string{"cacerts"},
	}
	kp2, err := kt2.getKeystorePath()
	if err != nil {
		t.Error(err)
	}
	if kp2 != kpath {
		t.Errorf("kp2=%s != kpath=%s", kp2, kpath)
	}

	err = os.RemoveAll(dir)
	if err != nil {
		t.Error(err)
	}
}
