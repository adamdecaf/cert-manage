package store

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/adamdecaf/cert-manage/tools/_x509"
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
			"/etc/alternatives/java",             // Linux
			"/Library/Java/JavaVirtualMachines/", // OSX

		},
		relativeKeystorePaths: []string{
			"/lib/security/cacerts",     // Linux and OSX
			"/jre/lib/security/cacerts", // OSX 10.10.1
		},
	}

	defaultKeystorePassword = "changeit"

	javaCertManageDir = "java"
)

type javaStore struct{}

func JavaStore() Store {
	return javaStore{}
}

func (s javaStore) Backup() error {
	kpath, err := ktool.getKeystorePath()
	if err != nil {
		return err
	}
	dir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		return err
	}

	// Rename the file as is
	_, filename := filepath.Split(kpath)
	dst := filepath.Join(dir, fmt.Sprintf("%s-%d.bck", filename, time.Now().Unix()))

	return file.CopyFile(kpath, dst)
}

func (s javaStore) List() ([]*x509.Certificate, error) {
	return ktool.getCertificates()
}

func (s javaStore) Remove(wh whitelist.Whitelist) error {
	kpath, err := ktool.getKeystorePath()
	if err != nil {
		return err
	}

	cs, err := ktool.listCertificateMetadata()
	if err != nil {
		return err
	}
	csfp, err := ktool.getCertificatesWithFingerprints()
	if err != nil {
		return err
	}

	// compare against all listed certs
	for i := range cs {
		cert := csfp[cs[i].fingerprint]
		if cert == nil {
			if debug {
				fmt.Printf("store/java: nil cert %s\n", cs[i].fingerprint)
			}
			continue
		}

		// Remove if we didn't match
		if !wh.Matches(cert) {
			err = ktool.deleteCertificate(kpath, cs[i].alias)
			if err != nil {
				return err
			}
			if debug {
				fmt.Printf("store/java: deleted %s (%s) from %s\n", cs[i].alias, cs[i].fingerprint, kpath)
			}
		}
	}

	return nil
}

func (s javaStore) Restore(where string) error {
	dir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		return err
	}
	src, err := getLatestBackupFile(dir)
	if err != nil {
		return err
	}

	// Get destination path
	dst, err := ktool.getKeystorePath()
	if err != nil {
		return err
	}

	// This sometimes requires escalated permissions because the `cacerts` file
	// is often owned by root or have perms like: -rw-rw-r-- (which prevent global writes)
	return file.SudoCopyFile(src, dst)
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

// expandSymlink takes in a symlink which refers to the `java` cli tool
// and attempts to return the home directory for that java install
//
// This shows up on linux flavors of /etc/alternatives/java which helps
// abstract over the java-$version-openjdk-$arch (or oracle) naming
func (k keytool) expandSymlink(p string) (string, error) {
	bin, err := os.Readlink(p)
	if err != nil {
		if _, ok := err.(*os.PathError); !ok {
			// The error was something other than path related, so return it, could be bad
			return "", err
		}
		return "", nil // path doesn't exist
	}
	if bin != "" {
		dir := strings.TrimSuffix(bin, "bin/java")
		if debug {
			fmt.Printf("store/java: expanded %s to %s and stripped to %s\n", p, bin, dir)
		}
		return filepath.Clean(dir), nil
	}
	return "", nil // again, no error if we failed
}

func (k keytool) getKeystorePath() (string, error) {
	kpath := k.javahome
	if kpath == "" {
		for i := range k.javaInstallPaths {
			// Sometimes javaInstallPaths can be a symlink, if so expand it and use that
			installPath := k.javaInstallPaths[i]
			if debug {
				fmt.Printf("store/java: searching %s\n", installPath)
			}
			dir, err := k.expandSymlink(installPath)
			if err != nil {
				return "", err
			}
			if dir != "" {
				installPath = dir
			}

			// Check each possible relative location
			for j := range k.relativeKeystorePaths {
				// Check if we've got a path now
				where := filepath.Join(installPath, k.relativeKeystorePaths[j])
				if file.Exists(where) {
					kpath = where
					break
				}
			}
			// If we've found something then quit
			if kpath != "" {
				if debug {
					fmt.Printf("store/java: found kpath %s\n", kpath)
				}
				break
			}
		}
	} else {
		// We've got JAVA_HOME, but need to add the relative path to `cacerts`
		for i := range k.relativeKeystorePaths {
			where := filepath.Join(kpath, k.relativeKeystorePaths[i])
			if file.Exists(where) {
				kpath = where
				if debug {
					fmt.Printf("store/java: found via JAVA_HOME %s\n", where)
				}
				break
			}
		}
	}
	// We never found a path which had a cacerts file
	if kpath == "" {
		return "", errors.New("store/java: never found java and/or keystore path")
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

func (k keytool) listCertificates(extraArgs ...string) ([]byte, error) {
	// `keytool` gets installed onto PATH, so no need to search for it
	kpath, err := k.getKeystorePath()
	if err != nil {
		return nil, err
	}

	args := append([]string{
		"-list",
		"-storepass", defaultKeystorePassword,
		"-keystore", kpath,
	}, extraArgs...)
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
	return stdout.Bytes(), nil
}

func (k keytool) getCertificates() ([]*x509.Certificate, error) {
	out, err := k.listCertificates("-rfc")
	if err != nil {
		return nil, err
	}

	// Parse output, it's a bunch of PEM blocks
	certs, err := pem.Parse(out)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func (k keytool) getCertificatesWithFingerprints() (map[string]*x509.Certificate, error) {
	out := make(map[string]*x509.Certificate, 0)

	certs, err := k.getCertificates()
	if err != nil {
		return out, err
	}

	for i := range certs {
		if certs[i] == nil {
			continue
		}

		fp := _x509.GetHexSHA1Fingerprint(*certs[i])
		out[fp] = certs[i]
	}

	return out, nil
}

type cert struct {
	alias       string
	fingerprint string
}

// $ keytool -list -keystore <path> -storepass <pass>
// Keystore type: JKS
// Keystore provider: SUN
//
// Your keystore contains 105 entries
//
// verisignclass2g2ca [jdk], Aug 25, 2016, trustedCertEntry,
// Certificate fingerprint (SHA1): B3:EA:C4:47:76:C9:C8:1C:EA:F2:9D:95:B6:CC:A0:08:1B:67:EC:9D
func (k keytool) listCertificateMetadata() ([]cert, error) {
	out, err := k.listCertificates()
	if err != nil {
		return nil, err
	}

	res := make([]cert, 0)
	r := bufio.NewScanner(bytes.NewReader(out))
	var prev, curr string
	for r.Scan() {
		prev = curr     // $alias [info....]
		curr = r.Text() // Certificate fingerprint ...

		// Do we have a cert?
		if strings.HasPrefix(curr, "Certificate fingerprint") {
			// verisignclass2g2ca [jdk], Aug 25, 2016, trustedCertEntry,
			alias := strings.TrimSpace(strings.Split(prev, ",")[0])
			var fingerprint string

			// Java 9 changes the fingerprint algorithm to SHA-256, which is identified inline
			// Certificate fingerprint (SHA1): B3:EA:C4:47:76:C9:C8:1C:EA:F2:9D:95:B6:CC:A0:08:1B:67:EC:9D
			// OR
			// Certificate fingerprint (SHA-256): 9A:CF:AB:7E:43:C8:D8:80:D0:6B:26:2A:94:DE:EE:E4:B4:65:99:89:C3:D0:CA:F1:9B:AF:64:05:E4:1A:B7:DF
			if strings.Contains(curr, "SHA1") {
				fingerprint = curr[len(curr)-40-19:] // 40 chars from sha1 output, 19 :'s
				fingerprint = strings.ToLower(strings.Replace(fingerprint, ":", "", -1))
			}
			if strings.Contains(curr, "SHA-256") {
				fingerprint = curr[len(curr)-64-31:] // 64 chars from sha1 output, 31 :'s
				fingerprint = strings.ToLower(strings.Replace(fingerprint, ":", "", -1))
			}

			if fingerprint == "" {
				if debug {
					fmt.Printf("store/java: Failed to determine fingerprint algorithm of: %s\n%s\n", alias, curr)
				}
				return nil, fmt.Errorf("Unable to determine fingerprint of cert %s", alias)
			}

			if debug {
				fmt.Printf("store/java: Parsed cert -- %s - %s \n", alias, fingerprint)
			}

			res = append(res, cert{
				alias:       alias,
				fingerprint: fingerprint,
			})
		}
	}

	return res, nil
}

// keytool -delete -alias <alias> -keystore <path> -storepass <pass>
// Pass kpath in so we don't have to rediscover it for every cert removal
func (k keytool) deleteCertificate(kpath, alias string) error {
	args := []string{
		"keytool",
		"-delete",
		"-alias", alias,
		"-keystore", kpath,
		"-storepass", defaultKeystorePassword,
	}
	cmd := exec.Command("sudo", args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if debug {
			fmt.Printf("Command was: %s\n", strings.Join(cmd.Args, " "))
			fmt.Printf("Stdout:\n%s\n", stdout.String())
			fmt.Printf("Stderr:\n%s\n", stderr.String())
		}
		return fmt.Errorf("%v when running keytool -delete %s", err.Error(), strings.TrimSpace(stdout.String()))
	}
	return nil
}
