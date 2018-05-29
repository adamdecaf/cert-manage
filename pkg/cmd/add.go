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
	"io/ioutil" 
	"os" 
 
	"github.com/adamdecaf/cert-manage/pkg/certutil" 
	"github.com/adamdecaf/cert-manage/pkg/store" 
) 
 
func AddCertsFromFile(where string) error { 
	st := store.Platform() 
	return addCerts(st, where) 
} 
 
func AddCertsToAppFromFile(app string, where string) error { 
	st, err := store.ForApp(app) 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
	return addCerts(st, where) 
} 
 
func addCerts(st store.Store, where string) error { 
	bs, err := ioutil.ReadFile(where) 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
	certs, err := certutil.Decode(bs) 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
	return st.Add(certs) 
} 
