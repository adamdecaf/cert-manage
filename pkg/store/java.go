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
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/adamdecaf/cert-manage/pkg/certutil"
	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

// Docs:
// - https://docs.oracle.com/cd/E19830-01/819-4712/ablqw/index.html
// - https://www.sslshopper.com/article-most-common-java-keytool-keystore-commands.html

var (
	defaultKeystorePassword = "changeit"
	javaCertManageDir       = "java"
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

func (s javaStore) GetInfo() *Info {
	return &Info{
		Name:    "Java",
		Version: s.version(),
	}
}

func (s javaStore) version() string {
	out, err := exec.Command("java", "-version").CombinedOutput()
	if err != nil {
		panic(err)
	}

	// e.g. java version "1.8.0_152"
	r := regexp.MustCompile(`"([\d\._]+)"`)
	m := r.FindString(string(out))
	return strings.Replace(m, `"`, "", -1)
}

func (s javaStore) List() ([]*x509.Certificate, error) {
	return ktool.getCertificates()
}

func (s javaStore) Remove(wh whitelist.Whitelist) error {
	kpath, err := ktool.getKeystorePath()
	if err != nil {
		return err
	}

	certs, err := ktool.getCertificates()
	if err != nil {
		return err
	}

	shortCerts, err := ktool.getShortCerts()
	if err != nil {
		return err
	}

	// compare against all listed certs
	for i := range shortCerts {
		if !shortCerts[i].hasFingerprints() {
			return fmt.Errorf("No fingerprints found for certificate %s", shortCerts[i])
		}

		// Find the cert
		for j := range certs {
			// Match the "short cert" to it's full x509.Certificate
			if shortCerts[i].matches(certs[j]) {
				// then remove if it's not whitelisted
				if !wh.Matches(certs[j]) {
					err = ktool.deleteCertificate(kpath, shortCerts[i].alias)
					if err != nil {
						return err
					}
					if debug {
						fmt.Printf("store/java: deleted %s from %s\n", shortCerts[i], kpath)
					}
				}
				break // skip to next "short cert"
			}
		}

		if debug {
			// We didn't match the "short cert" to it's full x509.Certificate
			fmt.Printf("store/java: Unable to find cert %s in java store at %s\n", shortCerts[i].alias, kpath)
		}
	}

	return nil
}

func (s javaStore) Restore(where string) error {
	dir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		return err
	}
	src, err := getLatestBackup(dir)
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

func (k keytool) getShortCertsRaw(extraArgs ...string) ([]byte, error) {
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
	out, err := k.getShortCertsRaw("-rfc")
	if err != nil {
		return nil, err
	}

	certs, err := certutil.ParsePEM(out)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

type cert struct {
	alias string

	// fingerprints
	sha1Fingerprint   string
	sha256Fingerprint string
}

func (c *cert) matches(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if c.sha1Fingerprint != "" {
		return certutil.GetHexSHA1Fingerprint(*cert) == c.sha1Fingerprint
	}
	if c.sha256Fingerprint != "" {
		return certutil.GetHexSHA256Fingerprint(*cert) == c.sha256Fingerprint
	}
	return false
}
func (c *cert) hasFingerprints() bool {
	return c.sha1Fingerprint != "" || c.sha256Fingerprint != ""
}
func (c *cert) String() string {
	if c.sha1Fingerprint != "" {
		return fmt.Sprintf("%s, SHA1=%s", c.alias, c.sha1Fingerprint)
	}
	if c.sha256Fingerprint != "" {
		return fmt.Sprintf("%s, SHA256=%s", c.alias, c.sha256Fingerprint)
	}
	return fmt.Sprintf("%s, but no fingerprints", c.alias)
}

// $ keytool -list -keystore <path> -storepass <pass>
// Keystore type: JKS
// Keystore provider: SUN
//
// Your keystore contains 105 entries
//
// verisignclass2g2ca [jdk], Aug 25, 2016, trustedCertEntry,
// Certificate fingerprint (SHA1): B3:EA:C4:47:76:C9:C8:1C:EA:F2:9D:95:B6:CC:A0:08:1B:67:EC:9D
func (k keytool) getShortCerts() ([]*cert, error) {
	out, err := k.getShortCertsRaw()
	if err != nil {
		return nil, err
	}

	res := make([]*cert, 0)
	r := bufio.NewScanner(bytes.NewReader(out))
	var prev, curr string
	for r.Scan() {
		prev = curr     // $alias [info....]
		curr = r.Text() // Certificate fingerprint ...

		// Do we have a cert?
		if strings.HasPrefix(curr, "Certificate fingerprint") {
			item := &cert{
				// verisignclass2g2ca [jdk], Aug 25, 2016, trustedCertEntry,
				alias: strings.TrimSpace(strings.Split(prev, ",")[0]),
			}

			// Java 9 changes the fingerprint algorithm to SHA-256, which is identified inline
			// Certificate fingerprint (SHA1): B3:EA:C4:47:76:C9:C8:1C:EA:F2:9D:95:B6:CC:A0:08:1B:67:EC:9D
			// OR
			// Certificate fingerprint (SHA-256): 9A:CF:AB:7E:43:C8:D8:80:D0:6B:26:2A:94:DE:EE:E4:B4:65:99:89:C3:D0:CA:F1:9B:AF:64:05:E4:1A:B7:DF
			if strings.Contains(curr, "SHA1") {
				fp := curr[len(curr)-40-19:] // 40 chars from sha1 output, 19 :'s
				fp = strings.ToLower(strings.Replace(fp, ":", "", -1))
				item.sha1Fingerprint = fp
			}
			if strings.Contains(curr, "SHA-256") {
				fp := curr[len(curr)-64-31:] // 64 chars from sha1 output, 31 :'s
				fp = strings.ToLower(strings.Replace(fp, ":", "", -1))
				item.sha256Fingerprint = fp
			}

			if !item.hasFingerprints() {
				if debug {
					fmt.Printf("store/java: Failed to determine fingerprint algorithm of: %s\n%s\n", item.alias, curr)
				}
				return nil, fmt.Errorf("Unable to determine fingerprint of cert: %s", item)
			}

			if debug {
				fmt.Printf("store/java: Parsed cert: %s\n", item)
			}

			res = append(res, item)
		}
	}

	return res, nil
}

// keytool -delete -alias <alias> -keystore <path> -storepass <pass>
// Pass kpath in so we don't have to rediscover it for every cert removal
func (k keytool) deleteCertificate(kpath, alias string) error {
	if strings.Contains(alias, "?") {
		// There seems to be an issue with aliases which contain certain characters. My guess
		// is that they're non-ascii and being encoded/decoded improperly.
		// I've filed a bug w/ openjdk (internal review ID 9051507), but until then
		// certs with these characters fail to be deleted.
		fmt.Printf("WARNING: alias %s cannot be currently removed from the keystore.\n", alias)
		return nil
	}

	args := []string{
		"keytool",
		"-delete",
		"-alias", alias,
		"-keystore", kpath,
		"-storepass", defaultKeystorePassword,
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		// already root
		cmd = exec.Command(args[0], args[1:]...)
	} else {
		cmd = exec.Command("sudo", args...)
	}

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
