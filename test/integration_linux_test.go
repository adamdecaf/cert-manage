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

package test

import (
	"testing"
)

func TestIntegration__date(t *testing.T) {
	t.Parallel()

	cmd := Command("date", "-u", "--date", "@0").Trim()
	cmd.EqualT(t, "Thu Jan  1 00:00:00 UTC 1970")
	cmd.SuccessT(t)
}

func TestIntegration__unknown(t *testing.T) {
	t.Parallel()

	cmd := CertManage("other").Trim()
	cmd.FailedT(t)
}
