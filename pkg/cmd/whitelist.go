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

package cmd

import (
	"fmt"
	"runtime"

	"github.com/adamdecaf/cert-manage/pkg/store"
	"github.com/adamdecaf/cert-manage/pkg/whitelist"
)

func WhitelistForApp(app, whpath string) error {
	// load whitelist
	wh, err := whitelist.FromFile(whpath)
	if err != nil {
		return err
	}

	// diff
	s, err := store.ForApp(app)
	if err != nil {
		return err
	}

	// check for a backup
	latest, err := s.GetLatestBackup()
	if err != nil {
		return fmt.Errorf("can't get latest %s backup err=%v", app, err)
	}
	if latest == "" {
		return fmt.Errorf("no backup for %s found", app)
	}

	// perform whitelist
	err = s.Remove(wh)
	if err != nil {
		return err
	}

	fmt.Println("Whitelist completed successfully")
	return nil
}

func WhitelistForPlatform(whpath string) error {
	// load whitelist
	wh, err := whitelist.FromFile(whpath)
	if err != nil {
		return err
	}

	// diff
	s := store.Platform()

	// check for backup
	latest, err := s.GetLatestBackup()
	if err != nil {
		return fmt.Errorf("can't get latest backup for %s err=%v", runtime.GOOS, err)
	}
	if latest == "" {
		return fmt.Errorf("no %s backup found", runtime.GOOS)
	}

	// perform whitelist
	err = s.Remove(wh)
	if err != nil {
		return err
	}

	fmt.Println("Whitelist completed successfully")
	return nil
}
