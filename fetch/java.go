package fetch

import (
	"crypto/x509"
	"github.com/adamdecaf/cert-manage/tools"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Docs:
// - https://docs.oracle.com/cd/E19830-01/819-4712/ablqw/index.html
// - https://www.sslshopper.com/article-most-common-java-keytool-keystore-commands.html

var (
	// These paths are all to be joined with JAVA_HOME
	cacertsFile = []string{
		"/lib/security/cacerts",	// Linux and OSX
		"/jre/lib/security/cacerts",	// OSX 10.10.1

	}
	cacertsPassword = "changeit"

	// Find java install paths
	javaInstallPaths = []string{
		`C:\Program Files\Java`,		// Windows
		"/Library/Java/JavaVirtualMachines/",	// OSX
		"/usr/lib/jvm/",			// Linux
		"/usr/java/",				// RHEL6
	}

)

// Java returns a slice of the certificates trusted by the installed
// java keystore on the running machine
func Java() ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, 50)
	paths := findJavaInstallPaths()

	// Build up certs
	for _, p := range paths {
		for _, f := range cacertsFile {
			fp := filepath.Join(p, f)
			if tools.FileExists(fp) {
				certs = append(certs, readCerts(fp)...)
			}
		}
	}

	return certs, nil
}

func readCerts(p string) []*x509.Certificate {
	p, err := filepath.Abs(p)
	if err != nil {
		return nil
	}

	b, err := exec.Command("keytool", "-list", "-rfc", "-storepass", cacertsPassword, "-keystore", p).Output()
	if err != nil {
		return nil
	}

	certs, err := tools.ParsePEMIntoCerts(b)
	if err != nil {
		return nil
	}

	return certs
}

func findJavaInstallPaths() []string {
	paths := make([]string, 0, 1)

	// Add whatever is under JAVA_HOME
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		if !contains(paths, jh) && tools.FileExists(jh) {
			paths = append(paths, jh)
		}
	}

	// Find path under default paths
	for _, p := range javaInstallPaths {
		if tools.FileExists(p) && !contains(paths, p) {
			paths = append(paths, p)
		}
	}

	return paths
}

func contains(s []string, e string) bool {
	if len(s) == 0 {
		return false
	}
	for i := range s {
		if strings.EqualFold(e, s[i]) {
			return true
		}
	}
	return false
}
