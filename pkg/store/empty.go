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
 
package store 
 
import ( 
	"crypto/x509" 
	"fmt" 
	"os" 
 
	"github.com/adamdecaf/cert-manage/pkg/whitelist" 
) 
 
// emptyStore represents a Store which has no implementation 
// This is useful for stubs 
type emptyStore struct{} 
 
func (s emptyStore) printNotce() { 
	fmt.Fprintln(os.Stderr, "NOTICE: This implementation is currently stubbed, nothing is happening.") 
} 
 
func (s emptyStore) Add(certs []*x509.Certificate) error { 
	s.printNotce() 
	return nil 
} 
 
func (s emptyStore) GetInfo() *Info { 
	return &Info{ 
		Name: "Empty", 
	} 
} 
func (s emptyStore) List(_ *ListOptions) ([]*x509.Certificate, error) { 
	s.printNotce() 
	return nil, nil 
} 
func (s emptyStore) Remove(whitelist.Whitelist) error { 
	s.printNotce() 
	return nil 
} 
func (s emptyStore) Restore(where string) error { 
	s.printNotce() 
	return nil 
} 
 
// Saver 
func (s emptyStore) Backup() error { 
	s.printNotce() 
	return nil 
} 
func (s emptyStore) GetLatestBackup() (string, error) { 
	s.printNotce() 
	return "", nil 
} 
