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

package test

import (
	"testing"
)

func TestAlpine__suite(t *testing.T) {
	t.Skip("TODO(adam): fix")
	t.Parallel()

	img := Dockerfile("envs/alpine")
	linuxSuite(t, img, cfg{
		total:        "151",
		after:        "5",
		curlExitCode: "60",
	})
}

func TestAlpine__java(t *testing.T) {
	t.Skip("TODO(adam): fix")
	t.Parallel()

	img := Dockerfile("envs/alpine")
	javaSuite(t, img, "150", "54")
}
