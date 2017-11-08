package file

import (
	"io/ioutil"
	"sort"
	"testing"
)

func TestFile__sortStrings(t *testing.T) {
	strings := []string{"b", "A", "C", "a", " ", ""}
	sort.Sort(iStringSlice(strings))
	answer := []string{"", " ", "A", "a", "b", "C"}

	for i := range strings {
		if strings[i] != answer[i] {
			t.Fatalf("idx: %d didn't match, %s vs %s", i, strings[i], answer[i])
		}
	}
}

func TestFile__sortNames(t *testing.T) {
	names := []string{"b", "A", "C", "a", " ", ""}
	sort.Sort(iStringSlice(names))
	answer := []string{"", " ", "A", "a", "b", "C"}

	for i := range names {
		if names[i] != answer[i] {
			t.Fatalf("idx: %d didn't match, %s vs %s", i, names[i], answer[i])
		}
	}
}

func TestFile__sortFileInfos(t *testing.T) {
	fds, err := ioutil.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	answers := []string{
		"file.go",
		"file_test.go",
		"file_unix.go",
		"file_windows.go",
		"sort.go",
		"sort_test.go",
	}

	for i := range fds {
		if fds[i].Name() != answers[i] {
			t.Fatalf("idx: %d didn't match, %s vs %s", i, fds[i].Name(), answers[i])
		}
	}
}
