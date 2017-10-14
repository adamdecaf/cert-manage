package file

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestFile__existsFile(t *testing.T) {
	loc := "file-test"
	if Exists(loc) {
		t.Fatalf("%s shouldn't exist", loc)
	}

	// Create
	f, err := os.Create(loc)
	if err != nil {
		t.Fatalf("err=%v creating %s", err, loc)
	}
	if !Exists(loc) || !Exists(f.Name()) {
		t.Fatalf("%s | %s should exist", loc, f.Name())
	}

	// Delete
	err = f.Close()
	if err != nil {
		t.Fatalf("%s should be closable, err=%v", loc, err)
	}
	err = os.Remove(loc)
	if err != nil {
		t.Fatalf("%s wasn't removable err=%v", loc, err)
	}
	if Exists(loc) || Exists(f.Name()) {
		t.Fatalf("%s | %s shouldn't exist anymore", loc, f.Name())
	}
}

func TestFile__existsDir(t *testing.T) {
	loc := "./test-dir"
	if Exists(loc) {
		t.Fatalf("%s shouldn't exist yet", loc)
	}

	// Create
	err := os.MkdirAll(loc, os.ModeDir)
	if err != nil {
		t.Fatal(err)
	}

	if !Exists(loc) {
		t.Fatalf("%s exists now", loc)
	}

	// Delete
	err = os.RemoveAll(loc)
	if err != nil {
		t.Fatal(err)
	}
	if Exists(loc) {
		t.Fatalf("%s doesn't exist anymore", loc)
	}
}


func TestFile__CopyFile(t *testing.T) {
	src := "file_test.go"
	dst := "copyfile-test"

	// copy
	err := CopyFile(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dst)

	// compare contents
	c1, err := ioutil.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s failed, err=%v", src, err)
	}
	c2, err := ioutil.ReadFile(dst)
	if err != nil {
		t.Fatalf("reading %s failed, err=%v", dst, err)
	}
	if string(c1) != string(c2) {
		t.Fatalf("%s and %s didn't match", src, dst)
	}
}
