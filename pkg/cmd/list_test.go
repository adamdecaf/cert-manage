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
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/adamdecaf/cert-manage/pkg/ui"
)

func TestCmdList__file(t *testing.T) {
	t.Parallel()

	cfg := ui.Config{
		Count: true,
	}
	err := ListCertsFromFile("../../testdata/example.crt", &cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCmdList__url(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, err := os.Open("../../testdata/certdata.txt.gz")
		if err != nil {
			t.Fatal(err)
		}
		r, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(w, r)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("no bytes written")
		}
	}))
	defer ts.Close()

	// Read certs from url
	cfg := ui.Config{
		Count: true,
	}
	err := ListCertsFromURL(fmt.Sprintf("http://%s", ts.Listener.Addr().String()), &cfg)
	if err != nil {
		t.Fatal(err)
	}
}
