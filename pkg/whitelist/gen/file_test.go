package gen

import (
	"reflect"
	"testing"
)

func TestGen_fromFile(t *testing.T) {
	urls, err := FromFile("../../../testdata/file-with-urls")
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 3 {
		t.Errorf("got %d urls", len(urls))
	}

	var ss []string
	for i := range urls {
		ss = append(ss, urls[i].String())
	}

	ans := []string{
		"https://google.com",
		"https://yahoo.com",
		"https://bing.com",
	}
	if !reflect.DeepEqual(ss, ans) {
		t.Errorf("got %q", ss)
	}
}
