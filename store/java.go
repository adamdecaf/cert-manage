package store

import (
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdecaf/cert-manage/tools/file"
	"github.com/adamdecaf/cert-manage/tools/pem"
	"github.com/adamdecaf/cert-manage/whitelist"
)

// Docs:
// - https://docs.oracle.com/cd/E19830-01/819-4712/ablqw/index.html
// - https://www.sslshopper.com/article-most-common-java-keytool-keystore-commands.html

var (
	// These paths are all to be joined with JAVA_HOME
	cacertsFile = []string{
		"/lib/security/cacerts",     // Linux and OSX
		"/jre/lib/security/cacerts", // OSX 10.10.1

	}
	cacertsPassword = "changeit"

	// Find java install paths
	javaInstallPaths = []string{
		`C:\Program Files\Java`,              // Windows
		"/Library/Java/JavaVirtualMachines/", // OSX
		"/usr/lib/jvm/",                      // Linux
		"/usr/java/",                         // RHEL6
	}
)

type javaStore struct{}

func JavaStore() Store {
	return javaStore{}
}

func (s javaStore) Backup() error {
	return nil
}

func (s javaStore) List() ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, 50)
	paths := findJavaInstallPaths()

	// Build up certs
	for _, p := range paths {
		for _, f := range cacertsFile {
			fp := filepath.Join(p, f)
			if file.Exists(fp) {
				certs = append(certs, readCerts(fp)...)
			}
		}
	}

	return certs, nil
}

func (s javaStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s javaStore) Restore(where string) error {
	return nil
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

	certs, err := pem.Parse(b)
	if err != nil {
		return nil
	}

	return certs
}

func findJavaInstallPaths() []string {
	paths := make([]string, 0, 1)

	// Add whatever is under JAVA_HOME
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		if !contains(paths, jh) && file.Exists(jh) {
			paths = append(paths, jh)
		}
	}

	// Find path under default paths
	for _, p := range javaInstallPaths {
		if file.Exists(p) && !contains(paths, p) {
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
