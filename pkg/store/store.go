package store

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

var (
	ErrNoBackupMade = errors.New("unable to make backup of store")

	// internal options
	debug = len(os.Getenv("DEBUG")) > 0 ||
		strings.Contains(os.Getenv("GODEBUG"), "x509roots=1")

	backupDirPerms os.FileMode = 0744

	// Define a mapping between -app and the Store instance
	appStores = map[string]Store{
		"chrome":  ChromeStore(),
		"firefox": FirefoxStore(),
		"java":    JavaStore(),
		"openssl": OpenSSLStore(),
	}
)

// Store represents a certificate store (often called 'pool') and has
// operations on it which mutate the underlying state (e.g. a file or
// directory).
type Store interface {
	// Add certificate(s) into the store
	Add([]*x509.Certificate) error

	// Backup will attempt to save a backup of the certificate store
	// on the local system
	Backup() error

	// List returns the currently trusted X509 certificates contained
	// within the cert store
	List() ([]*x509.Certificate, error)

	// Remove will distrust the certificate in the store
	//
	// Note: This may not actually delete the certificate, but modify
	// the store such that the certificate is no longer trusted.
	// This is done when possible to limit the actual deletions to
	// preserve restore capabilities
	Remove(whitelist.Whitelist) error

	// Restore will bring the system back to it's previous state
	// if a backup exists, otherwise it will attempt to bring the
	// cert trust status to the system's default state
	//
	// Optionally, this can take a specific filepath to use as the
	// restore point. This may not be supported on all stores.
	//
	// Note: It is strongly advised that any additional certs installed
	// be verified are still properly installed and working after
	// Restore() is called.
	Restore(where string) error
}

// Platform returns a new instance of Store for the running os/platform
func Platform() Store {
	return platform()
}

// GetApps returns an array the supported app names
func GetApps() []string {
	var out []string
	for k := range appStores {
		out = append(out, k)
	}
	file.SortNames(out)
	return out
}

// ForApp returns a `Store` instance for the given app
func ForApp(app string) (Store, error) {
	s, ok := appStores[strings.ToLower(app)]
	if !ok {
		return nil, fmt.Errorf("application '%s' not found", app)
	}
	return s, nil
}

// getCertManageDir returns the fs location (always creating first) where a specific
// store can save files into. This path is recommended for backups
//
// If `name` is an absolute fs reference then just ensure that directory is created
// and has permissions setup properly.
func getCertManageDir(name string) (string, error) {
	parent, err := getCertManageParentDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(parent, name)
	// If `name` is actually an absolute fs reference then just ensure
	// it's created and owned properly, otherwise append whatever was
	// provided onto the parent dir.
	if filepath.IsAbs(name) {
		s, err := os.Stat(name)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if s != nil && !s.IsDir() {
			return "", fmt.Errorf("since %s exists and cannot be a file, should be a dir", name)
		}
		dir = name
	}

	// Create the dir and set ownership
	err = os.MkdirAll(dir, os.ModeDir|backupDirPerms)
	if err != nil {
		return "", err
	}

	return dir, nil
}

func getCertManageParentDir() (string, error) {
	uhome := file.HomeDir()
	if uhome != "" {
		parent := ""

		// Setup parent dir
		if runtime.GOOS == "darwin" {
			parent = filepath.Join(uhome, "/Library/cert-manage")
		}
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
			parent = filepath.Join(uhome, ".cert-manage")
		}

		// Make parent dir and set ownership
		err := os.MkdirAll(parent, os.ModeDir|backupDirPerms)
		if err != nil {
			return "", err
		}
		return parent, nil
	}
	return "", nil
}

// getLatestBackup returns the "biggest" file or dir at a given path
//
// This sorting is done by assuming filenames follow a pattern like
// file-%d.ext where %d is a sortable timestamp and the filename follows
// lexigraphical sorting. Results are sorted in descending order and the
// first element (if exists) is returned
func getLatestBackup(dir string) (string, error) {
	fis, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}
	if len(fis) == 0 {
		return "", nil
	}

	// get largest
	file.SortFileInfos(fis)
	latest := fis[len(fis)-1]
	return filepath.Join(dir, latest.Name()), nil
}
