package store

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestNSS_certdbDiscovery(t *testing.T) {
	// create a dir, add a 'cert8.db' file and verify we can discover it
	tmp, err := ioutil.TempDir("", "nss-discovery")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmp)

	// Very we don't find anything in an empty dir
	if len(collectNssSuggestions([]string{tmp})) > 0 {
		t.Errorf("shouldn't have found cert8.db files in %s", tmp)
	}
	if containsCert8db(tmp) {
		t.Errorf("%s shouldn't contain a cert8.db", tmp)
	}

	// Create a blank cert8.db file
	where := filepath.Join(tmp, "cert8.db")
	err = ioutil.WriteFile(where, []byte("data"), 0644)
	if err != nil {
		t.Error(err)
	}

	// Now we should find the cert8.db path
	if !containsCert8db(tmp) {
		t.Errorf("should have found cert8.db in %s", tmp)
	}
	sugs := collectNssSuggestions([]string{tmp})
	if len(sugs) != 1 {
		t.Errorf("should have found cert8.db in %s", sugs)
	}
}
