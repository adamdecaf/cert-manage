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
	"fmt"
	"os"
)

// showCertsOnCli outputs the slice of certificates in `cfg.Format` to stdout
func showCertsOnCli(certs []*x509.Certificate, cfg *Config) error {
	p, ok := getPrinter(cfg.Format)
	if !ok {
		return fmt.Errorf("unknown format %s specified", cfg.Format)
	}
	return showCertsOnCliWithPrinter(certs, cfg, p)
}

func showCertsOnCliWithPrinter(certs []*x509.Certificate, cfg *Config, p printer) error {
	if tp, ok := p.(tablePrinter); ok {
		tp.verbose = cfg != nil && cfg.Verbose
		if cfg != nil {
			tp.path = cfg.SourcePath
		}
		p = tp
	}
	err := p.write(os.Stdout, certs)
	p.close()
	return err
}
