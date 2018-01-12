// +build linux

package store

import (
	"os"
)

var ktool = keytool{
	javahome: os.Getenv("JAVA_HOME"),
	javaInstallPaths: []string{
		"/etc/alternatives/java",
	},
	relativeKeystorePaths: []string{
		"/lib/security/cacerts",
		"/jre/lib/security/cacerts", // alpine
	},
}
