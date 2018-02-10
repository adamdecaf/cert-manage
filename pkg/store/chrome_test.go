package store

import (
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

func TestStoreChrome__info(t *testing.T) {
	// TOOD(adam): Support other OS's
	if file.Exists(`/Applications/Google Chrome.app`) {
		ver := chromeVersion()
		if ver == "" {
			t.Error("blank Version")
		}
	}
}
