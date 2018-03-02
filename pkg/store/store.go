// Copyright 2018 Adam Shannon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/file"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

var (
	// internal options
	debug = len(os.Getenv("DEBUG")) > 0 ||
		strings.Contains(os.Getenv("GODEBUG"), "x509roots=1")

	// Define a mapping between -app and the Store instance
	appStores = map[string]Store{
		"chrome":  ChromeStore(),
		"firefox": FirefoxStore(),
		"java":    JavaStore(),
		"openssl": OpenSSLStore(),
	}
)

type ListOptions struct {
	// Include "trusted" certificates
	// This represents what'a good acting application or would return
	Trusted bool

	// Include certificates specifically untrusted by a user/admin
	Untrusted bool

	// TODO(adam): Expired and Revoked
}

type Lister interface {
	// List returns the currently trusted X509 certificates contained
	// within the cert store
	List(opts *ListOptions) ([]*x509.Certificate, error)
}

type Modifier interface {
	// Add certificate(s) into the store
	Add([]*x509.Certificate) error

	// Remove will distrust the certificate in the store
	//
	// Note: This may not actually delete the certificate, but modify
	// the store such that the certificate is no longer trusted.
	// This is done when possible to limit the actual deletions to
	// preserve restore capabilities
	Remove(whitelist.Whitelist) error
}

// Store represents a certificate store (set of x509 Certificates) and has
// operations on it which can mutate the underlying state (e.g. a file or
// directory).
type Store interface {
	Lister
	Modifier
	Saver

	// GetInfo returns basic information about the store
	GetInfo() *Info
}

// Info represents high-level information about a certificate store
// There are no guarentees of machine parsing on this data, but it should
// be easily human readable.
type Info struct {
	Name    string
	Version string
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
		return nil, fmt.Errorf("application %q not found", app)
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
