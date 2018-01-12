// +build windows

package store

import (
	"os"
)

var ktool = keytool{
	javahome:              os.Getenv("JAVA_HOME"),
	javaInstallPaths:      []string{},
	relativeKeystorePaths: []string{},
}
