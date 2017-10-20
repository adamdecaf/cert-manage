package file

import (
	"reflect"
	"sort"
	"testing"
)

func TestFile__sortStrings(t *testing.T) {
	strings := []string{"b", "A", "C", "a", " ", ""}
	sort.Sort(iStringSlice(strings))
	answer := []string{"", " ", "A", "a", "b", "C"}
	if !reflect.DeepEqual(strings, answer) {
		t.Fatalf("sorted strings don't equal answer, strings=%v", strings)
	}
}
