package store

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

// From: https://www.chromium.org/Home/chromium-security/root-ca-policy
func ChromeStore() Store {
	switch runtime.GOOS {
	case "darwin", "windows":
		// TODO(adam): GetInfo() here would return OS info, not apps
		return Platform()
	case "linux":
		return chromeLinux()
	}
	return emptyStore{}
}

func chromeCertdbLocations() []cert8db {
	uhome := file.HomeDir()
	if uhome == "" {
		if debug {
			fmt.Println("store/chrome: unable to find user's home dir")
		}
		return nil
	}

	return []cert8db{
		cert8db(filepath.Join(uhome, ".pki/nssdb")),
	}
}

func chromeLinux() Store {
	suggestions := chromeCertdbLocations()
	found := locateCert8db(suggestions)
	return NssStore("chrome", chromeVersion(), suggestions, found)
}

// Format like: "Google Chrome 63.0.3239.132"
func chromeVersion() string {
	// TODO(adam): Support other OS's (and probably Chromium)
	out, err := exec.Command(`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, "--version").CombinedOutput()
	if err != nil {
		panic(err)
	}
	return strings.Replace(string(out), "Google Chrome", "", -1)
}
