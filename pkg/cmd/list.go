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
	"io" 
	"io/ioutil" 
	"os" 
 
	"github.com/adamdecaf/cert-manage/pkg/certutil" 
	"github.com/adamdecaf/cert-manage/pkg/httputil" 
	"github.com/adamdecaf/cert-manage/pkg/store" 
	"github.com/adamdecaf/cert-manage/pkg/ui" 
) 
 
var ( 
	maxDownloadSize int64 = 10 * 1024 * 1024 // bytes 
) 
 
// ListCertsFromFile finds certificates at the given filepath 
// and lists them according to the ui/format options. 
func ListCertsFromFile(where string, cfg *ui.Config) error { 
	bs, err := ioutil.ReadFile(where) 
	if err != nil { 
		return err 
	} 
	certs, err := certutil.Decode(bs) 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
	return ui.ListCertificates(certs, cfg) 
} 
 
// ListCertsFromURL downloads a url and shows the certificates 
// according to the ui/format options. 
func ListCertsFromURL(where string, cfg *ui.Config) (err error) { 
	client := httputil.New() 
	resp, err := client.Get(where) 
	defer func() { 
		if resp.Body != nil { 
			err = resp.Body.Close() 
		} 
	}() 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
 
	// read out certs 
	r := io.LimitReader(resp.Body, maxDownloadSize) 
	bs, err := ioutil.ReadAll(r) 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
	certs, err := certutil.Decode(bs) 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
	return ui.ListCertificates(certs, cfg) 
} 
 
// ListCertsForPlatform finds certs for the given platform. 
// The supported platforms can be found in the readme. They're compiled in 
// with build flags in the `certs/find_*.go` files. 
func ListCertsForPlatform(cfg *ui.Config) error { 
	st := store.Platform() 
	certificates, err := st.List(&store.ListOptions{ 
		Trusted: true, 
	}) 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
	meta := createMeta(st) 
	return ui.ListCertificatesWithMeta(meta, certificates, cfg) 
} 
 
// ListCertsForApp finds certs for the given app. 
// The supported applications are listed in the readme. This includes 
// non-traditional applications like NSS. 
func ListCertsForApp(app string, cfg *ui.Config) error { 
	st, err := store.ForApp(app) 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
 
	certificates, err := st.List(&store.ListOptions{ 
		Trusted: true, 
	}) 
	if err != nil { 
		fmt.Println(err) 
		os.Exit(1) 
	} 
 
	// Break if we had some error 
	if err != nil { 
		fmt.Printf("error finding certificates for application %s\n", err) 
		os.Exit(1) 
	} 
 
	// Output the certificates 
	meta := createMeta(st) 
	return ui.ListCertificatesWithMeta(meta, certificates, cfg) 
} 
 
func createMeta(st store.Store) ui.Meta { 
	info := st.GetInfo() 
	return ui.Meta{ 
		Name:    info.Name, 
		Version: info.Version, 
	} 
} 
