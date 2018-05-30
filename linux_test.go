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

package main

// Run `go test` in docker images locally
// This will skip tests if docker isn't enabled / running
// or if the platform is linux (all docker images are linux)

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"

	docker "github.com/adamdecaf/cert-manage/test"
)

var (
	// docker image tags which are required to pass
	stableTags = []string{
		"1.10-alpine3.7",
		"1.10-stretch",
	}

	// docker image tags which can fail
	unstableTags = []string{}
)

func TestLinux__stable(t *testing.T) {
	runTests(t, stableTags, true)
}

func TestLinux__unstable(t *testing.T) {
	runTests(t, unstableTags, false)
}

func setup(t *testing.T) {
	t.Helper()

	if runtime.GOOS == "linux" {
		t.Skip("already on linux")
	}

	if !docker.IsDockerEnabled() {
		t.Skip("docker isn't enabled/supported")
	}
}

func runTests(t *testing.T, tags []string, stable bool) {
	t.Helper()
	t.Parallel()
	setup(t)

	wg := sync.WaitGroup{}
	wg.Add(len(tags))
	for i := range tags {
		go func(t *testing.T, wg *sync.WaitGroup, tag string, stable bool) {
			defer wg.Done()
			runTest(t, tag, stable)
		}(t, &wg, tags[i], stable)
	}
	wg.Wait()
}

func runTest(t *testing.T, tag string, stable bool) {
	t.Helper()

	dir, _ := os.Getwd()
	if dir == "" {
		t.Fatal("empty workdir")
	}
	image := fmt.Sprintf("golang:%s", tag)
	workdir := "/go/src/github.com/adamdecaf/cert-manage"
	args := []string{
		"run", "--rm",
		"-v", fmt.Sprintf("%s:%s", dir, workdir),
		"-w", workdir,
		image,
		"go", "test", "./...",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		msg := fmt.Sprintf("tests failed for %s\n%s\n", image, string(out))
		if stable {
			t.Error(msg)
		} else {
			t.Skip(msg)
		}
	}
}
