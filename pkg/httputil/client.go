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
 
package httputil 
 
import ( 
	"crypto/tls" 
	"net" 
	"net/http" 
	"time" 
) 
 
var ( 
	// https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/ 
	client = &http.Client{ 
		// Never follow redirects, return body 
		CheckRedirect: func(req *http.Request, via []*http.Request) error { 
			return http.ErrUseLastResponse 
		}, 
		Transport: &http.Transport{ 
			DialContext: (&net.Dialer{ 
				Timeout:   30 * time.Second, 
				KeepAlive: 30 * time.Second, 
				DualStack: true, 
			}).DialContext, 
			TLSClientConfig: &tls.Config{ 
				MinVersion: tls.VersionTLS12, 
				MaxVersion: tls.VersionTLS12, 
			}, 
			TLSHandshakeTimeout:   1 * time.Minute, 
			IdleConnTimeout:       1 * time.Minute, 
			ResponseHeaderTimeout: 1 * time.Minute, 
			ExpectContinueTimeout: 1 * time.Minute, 
		}, 
		Timeout: 30 * time.Second, 
	} 
) 
 
func New() *http.Client { 
	return client 
} 
