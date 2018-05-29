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
	"crypto/x509" 
	"errors" 
	"fmt" 
	"strings" 
) 
 
type uiface func(certs []*x509.Certificate, cfg *Config) error 
 
var ( 
	cliFormat = "cli" 
 
	uiOptions = map[string]uiface{ 
		cliFormat: showCertsOnCli, 
		"web":     showCertsOnWeb, 
	} 
) 
 
// UI - what technology to display results on 
func DefaultUI() string { 
	return cliFormat 
} 
func GetUIs() []string { 
	var out []string 
	for k := range uiOptions { 
		out = append(out, k) 
	} 
	return out 
} 
 
type Config struct { 
	// If we should only show the certificate count, rather than each one 
	Count bool 
 
	// What format to print certificates in, formats are defined in ../main.go and 
	// checked in print.go 
	Format string 
 
	// Outfile holds where to write the output to. Used if non-empty 
	Outfile string 
 
	// Which user interface to show users, e.g. cli or web 
	// Default (and possible) value(s) can be found in the ui package 
	UI string 
} 
 
func ListCertificates(certs []*x509.Certificate, cfg *Config) error { 
	if cfg.Count { // ignore any cfg.UI setting 
		fmt.Printf("%d\n", len(certs)) 
		return nil 
	} 
 
	// Show something meaningful if there's nothing otherwise 
	if len(certs) == 0 { 
		return errors.New("No certififcates to display") 
	} 
 
	fn, ok := uiOptions[strings.ToLower(cfg.UI)] 
	if !ok { 
		return fmt.Errorf("Unknown ui %q", cfg.UI) 
	} 
	return fn(certs, cfg) 
} 
 
// Meta is used to add additional details on the certficiate store 
type Meta struct { 
	Name    string 
	Version string 
} 
 
func ListCertificatesWithMeta(meta Meta, certs []*x509.Certificate, cfg *Config) error { 
	if isObservatory(cfg.Format) { 
		return writeObservatoryReport(meta, certs, cfg) 
	} 
	return ListCertificates(certs, cfg) 
} 
