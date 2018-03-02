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
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/adamdecaf/cert-manage/pkg/file"
)

var (
	// ErrNoBackupMade is returned if no backup of a certificate store can be found
	ErrNoBackupMade = errors.New("unable to make backup of store")

	backupDirPerms os.FileMode = file.TempDirPermissions
)

// Saver is an interface which represents making a copy of a certificate
// store to a well-known filesystem path.
type Saver interface {
	// Backup will attempt to save a backup of the certificate store
	// on the local system
	Backup() error

	// GetLatestBackup returns the latest directory (or file) backup
	// of a certificate store.
	//
	// If the path is non-empty the directory or file is guarenteed
	// to exist.
	GetLatestBackup() (string, error)

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
