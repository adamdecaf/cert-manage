// +build darwin

package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/cert-manage/tools/file"
)

var ktool keytool

func init() {
	full := expandKnownJavaInstall()
	if full == "" {
		full = "/Library/Java/JavaVirtualMachines/"
	}

	ktool = keytool{
		javahome:         os.Getenv("JAVA_HOME"),
		javaInstallPaths: []string{full},
		relativeKeystorePaths: []string{
			"/lib/security/cacerts",
			"/jre/lib/security/cacerts", // OSX 10.10.1
		},
	}
}

func expandKnownJavaInstall() string {
	full := "/System/Library/Frameworks/JavaVM.framework/Versions/Current/Commands/java_home"
	if file.Exists(full) && file.IsExecutable(full) {
		// We need to exec the script and return its result as JAVA_HOME
		out, err := exec.Command(full).Output()
		if err != nil {
			// return we found nothing
			return ""
		}
		return filepath.Clean(strings.TrimSpace(string(out)))
	}
	return ""
}
