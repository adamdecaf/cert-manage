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

//go:build windows
// +build windows

package store

import (
	"testing"
)

func TestStoreWindows__list(t *testing.T) {
	st := windowsStore{}
	certs, err := st.List(&ListOptions{})
	if err != nil {
		t.Fatalf("problem listing certs: %v", err)
	}
	if len(certs) <= 0 {
		t.Fatal("found no certificates")
	}
}

func TestStoreWindows__getInfo(t *testing.T) {
	info := Platform().GetInfo()
	if info == nil {
		t.Fatal("nil Info")
	}
	if info.Name == "" {
		t.Error("blank Name")
	}
	if info.Version == "" {
		t.Error("blank Version")
	}
}
