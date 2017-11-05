package store

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
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
	ktool = keytool{
		javahome: os.Getenv("JAVA_HOME"),
		javaInstallPaths: []string{
			"/usr/lib/jvm/",                      // Linux
			"/Library/Java/JavaVirtualMachines/", // OSX
			// `C:\Program Files\Java`,              // Windows

		},
		relativeKeystorePaths: []string{
			"/lib/security/cacerts",     // Linux and OSX
			"/jre/lib/security/cacerts", // OSX 10.10.1
		},
	}

	defaultKeystorePassword = "changeit"
)

type javaStore struct{}

func JavaStore() Store {
	return javaStore{}
}

func (s javaStore) Backup() error {
	return nil
}

func (s javaStore) List() ([]*x509.Certificate, error) {
	return ktool.getCertificates()
}

func (s javaStore) Remove(wh whitelist.Whitelist) error {
	return nil
}

func (s javaStore) Restore(where string) error {
	return nil
}

type keytool struct {
	// JAVA_HOME env variable
	javahome string

	// Where is java installed, default is to look at JAVA_HOME
	javaInstallPaths []string

	// Under java install path where is the `cacerts` keystore located?
	// This changes on each platform...
	relativeKeystorePaths []string
}

func (k keytool) getKeystorePath() (string, error) {
	kpath := k.javahome
	if kpath == "" {
		for i := range k.javaInstallPaths {
			for j := range k.relativeKeystorePaths {
				where := filepath.Join(k.javaInstallPaths[i], k.relativeKeystorePaths[j])
				if file.Exists(where) {
					kpath = where
					break
				}
			}
			// If we've found something then quit
			if kpath != "" {
				break
			}
		}
	} else {
		// We've got JAVA_HOME, but need to add the relative path to `cacerts`
		for i := range k.relativeKeystorePaths {
			where := filepath.Join(kpath, k.relativeKeystorePaths[i])
			if file.Exists(where) {
				kpath = where
				break
			}
		}
	}
	// We never found a path which had a cacerts file
	if kpath == "" {
		return "", errors.New("Unable to find java and/or keystore path")
	}

	// Verify it's a non-empty file
	s, err := os.Stat(kpath)
	if err != nil {
		return "", err
	}
	if s.Size() == 0 {
		return "", fmt.Errorf("Found keystore at %s, but it's an empty file", kpath)
	}

	return kpath, nil
}

func (k keytool) getCertificates() ([]*x509.Certificate, error) {
	// `keytool` gets installed onto PATH, so no need to search for it
	kpath, err := k.getKeystorePath()
	if err != nil {
		return nil, err
	}

	args := []string{
		"-list",
		"-rfc",
		"-storepass", defaultKeystorePassword,
		"-keystore", kpath,
	}
	cmd := exec.Command("keytool", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was: %s\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Stdout:\n%s\n", stdout.String())
			fmt.Printf("Stderr:\n%s\n", stderr.String())
		}
		return nil, err
	}

	// Parse output, it's a bunch of PEM blocks
	certs, err := pem.Parse(stdout.Bytes())
	if err != nil {
		return nil, err
	}
	return certs, nil
}
