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
	st, err := store.ForApp(app)
	if err != nil {
		return err
	}
	err = st.Remove(wh)
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
	st := store.Platform()
	err = st.Remove(wh)
	if err != nil {
		return err
	}

	fmt.Println("Whitelist completed successfully")
	return nil
}
