package store

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreJava__expandSymlink(t *testing.T) {
	// Make a symlink to a cacerts file
	dir, err := ioutil.TempDir("", "cert-manage-java")
	if err != nil {
		t.Error(err)
	}
	kpath := filepath.Join(dir, "cacerts")
	err = ioutil.WriteFile(kpath, []byte("A"), 0666)
	if err != nil {
		t.Error(err)
	}
	// create the symlink
	other := "java-certs"
	err = os.Symlink(kpath, other)

	// Verify it's found
	kt1 := keytool{}
	out, err := kt1.expandSymlink(other)
	if err != nil || out == "" {
		t.Fatalf("%s should have been seen as a symlink to %s, err=%v", other, kpath, err)
	}
	err = os.Remove(other)
	if err != nil {
		t.Error(err)
	}

	// Verify bin/java can be removed
	err = os.MkdirAll("other/bin", 0777|os.ModeDir)
	if err != nil {
		t.Error(err)
	}
	err = os.Symlink(filepath.Join(dir, "bin/java"), "other/bin/java")
	if err != nil {
		t.Error(err)
	}
	p, _ := kt1.expandSymlink("other/bin/java")
	if p != dir {
		t.Errorf("%s should have been %s", p, dir)
	}
	os.RemoveAll("other/")
}

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

func TestStoreJava__info(t *testing.T) {
	info := JavaStore().GetInfo()
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
