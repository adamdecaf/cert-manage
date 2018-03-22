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

package gen

import (
	"time"
)

func init() {
	// The "last visit dates" in our test browser history files are static
	// and so limiting urls which only were accessed in the last N days will
	// eventually cut off all urls. We need to set this back to some date
	// which will allow all records in our test history files to be collected.
	oldestBrowserHistoryItemDate = time.Date(2010, time.January, 1, 0, 0, 0, 0, time.UTC)
}
