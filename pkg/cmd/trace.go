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
	"os" 
	"runtime/trace" 
) 
 
func NewTrace(where string) (*Trace, error) { 
	if where == "" { 
		return nil, nil 
	} 
 
	fd, err := os.Create(where) 
	if err != nil { 
		return nil, fmt.Errorf("error creating trace, err=%v", err) 
	} 
 
	return &Trace{ 
		fd: fd, 
	}, nil 
} 
 
type Trace struct { 
	fd *os.File 
} 
 
func (t *Trace) Start() error { 
	if t == nil { 
		return nil 
	} 
	return trace.Start(t.fd) 
} 
 
func (t *Trace) Stop() error { 
	if t == nil { 
		return nil 
	} 
 
	trace.Stop() 
	return t.fd.Close() 
} 
