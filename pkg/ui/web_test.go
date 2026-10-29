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

package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWritePrinterFailureIncludesClose(t *testing.T) {
	var buf bytes.Buffer
	writePrinterFailure(&buf, errors.New("openssl unavailable"))
	out := buf.String()
	if !strings.Contains(out, "ERROR: openssl unavailable") {
		t.Fatalf("missing error text:\n%s", out)
	}
	if !strings.Contains(out, `href="/done"`) || !strings.Contains(out, "Close") {
		t.Fatalf("missing Close action:\n%s", out)
	}
}
