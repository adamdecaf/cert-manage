package file

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestFile__isExecutable(t *testing.T) {
	if IsExecutable("../../testdata/example.crt") {
		t.Error("file isn't executable")
	}

	ex, err := os.Executable()
	if err != nil {
		t.Error(err)
	}
	if !IsExecutable(ex) {
		t.Errorf("go should be executable: %s", ex)
	}
}

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

func TestFile__MirrorDir(t *testing.T) {
	src := "../ui"
	dst, err := ioutil.TempDir("", "cert-manage-file-test")
	if err != nil {
		t.Fatal(err)
	}

	// Throw in a symlink for fun
	err = os.Symlink("./ui.go", "../ui/f")
	if err != nil {
		t.Fatal(err.(*os.LinkError).Err)
	}
	defer os.Remove("../ui/f")

	// mirror
	err = MirrorDir(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dst)

	// Verify the structure is valid
	checks := []struct {
		rel string // relative path after `src` or `dst`
	}{
		// dirs
		{"server"},
		// symlinks
		{"f"},
		//files
		{"ui.go"},
		{"server/server.go"},
	}
	for _, c := range checks {
		sp := filepath.Join(src, c.rel)
		s, _ := os.Stat(sp)
		dp := filepath.Join(dst, c.rel)
		d, _ := os.Stat(dp)

		// compare them as dirs
		if s.IsDir() && d.IsDir() {
			if s.Name() != d.Name() {
				t.Fatalf("%s != %s", s.Name(), d.Name())
			}
			if s.Mode() != d.Mode() {
				t.Fatalf("%s(%v) != %s(%v)", s.Name(), s.Mode(), d.Name(), d.Mode())
			}
			continue
		}
		// compare as symlinks
		if f1, e1 := os.Readlink(sp); e1 == nil && s.Mode()&os.ModeSymlink == 0 && d.Mode()&os.ModeSymlink == 0 {
			// f1, e1 := os.Readlink(sp)
			f2, e2 := os.Readlink(dp)
			if e1 != nil || e2 != nil {
				t.Fatalf("s=%s, e1=%v, d=%s, e2=%v", sp, e1, dp, e2)
			}
			if f1 != f2 {
				t.Fatalf("f1=%s, f2=%s", f1, f2)
			}
			continue
		}
		// compare them as files
		if s.Mode().IsRegular() && s.Mode().IsRegular() {
			// compare them as files
			if s.Size() != d.Size() || s.Mode() != d.Mode() {
				t.Fatalf("%s and %s aren't the same", s.Name(), d.Name())
			}
			continue
		}

		// no check done
		t.Fatalf("no checking done on %s, %s pair", sp, dp)
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
