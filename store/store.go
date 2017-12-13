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

	"github.com/adamdecaf/cert-manage/tools/file"
	"github.com/adamdecaf/cert-manage/whitelist"
)

var (
	ErrNoBackupMade = errors.New("unable to make backup of store")

	// internal options
	debug = len(os.Getenv("TRAVIS_OS_NAME")) > 0 ||
		len(os.Getenv("DEBUG")) > 0 ||
		strings.Contains(os.Getenv("GODEBUG"), "x509roots=1")

	backupDirPerms os.FileMode = 0744

	// Define a mapping between -app and the Store instance
	appStores = map[string]Store{
		"chrome":  ChromeStore(),
		"firefox": FirefoxStore(),
		"java":    JavaStore(),
	}
)

// Store represents a certificate store (often called 'pool') and has
// operations on it which mutate the underlying state (e.g. a file or
// directory).
type Store interface {
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
func getCertManageDir(name string) (string, error) {
	parent := getCertManageParentDir()
	err := os.MkdirAll(parent, os.ModeDir)
	if err != nil {
		return "", err
	}
	err = os.Chmod(parent, backupDirPerms)
	if err != nil {
		return "", err
	}

	// Create the child dir now
	child := filepath.Join(parent, name)
	err = os.MkdirAll(child, os.ModeDir)
	if err != nil {
		return "", err
	}
	err = os.Chmod(child, backupDirPerms)
	if err != nil {
		return "", err
	}

	return child, nil
}

func getCertManageParentDir() string {
	uhome := file.HomeDir()
	if uhome != "" {
		// Setup parent dir
		if runtime.GOOS == "darwin" {
			return filepath.Join(uhome, "/Library/cert-manage")
		}
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
			return filepath.Join(uhome, ".cert-manage")
		}
	}
	return ""
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
