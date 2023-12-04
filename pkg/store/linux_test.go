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

//go:build linux
// +build linux

package store

import (
	"runtime"
	"testing"
)

func TestStoreLinux__cadir(t *testing.T) {
	// just grab the linuxStore and make sure it has a cadir member
	s, ok := platform().(linuxStore)
	if !ok {
		t.Error("error casting to linuxStore")
	}
	if s.ca.empty() {
		t.Errorf("no cadir found on platform: %s", runtime.GOOS)
	}
}
