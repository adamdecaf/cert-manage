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

func TestDocker_basic(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/basic")
	img.Run("date", "-u")
	img.SuccessT(t)
}

func TestDocker_hasSuffix(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/basic/Dockerfile")
	img.Run("date", "-u")
	img.SuccessT(t)
}

func TestDocker_shouldFail(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/basic")
	img.ShouldFail("nothing")
	img.SuccessT(t)

	img = Dockerfile("envs/basic")
	img.ShouldFail("nothing", "other")
	img.SuccessT(t)
}

func TestDocker__exitCode(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/basic")
	img.ExitCode("0", "date")
	img.ExitCode("127", "asjdsfjsafkjas")
	img.SuccessT(t)
}
