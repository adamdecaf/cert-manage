package store

import (
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

func TestStoreFirefix__info(t *testing.T) {
	st := FirefoxStore()

	// TOOD(adam): Support other OS's
	if file.Exists("/Applications/Firefox.app") {
		info := st.GetInfo()
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
}
