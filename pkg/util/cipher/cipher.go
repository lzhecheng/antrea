// Copyright 2021 Antrea Authors
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

package cipher

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"k8s.io/client-go/rest"
	"net/http"
	"strings"

	"k8s.io/component-base/cli/flag"
)

// RawCipherSuitesStrToCipherSuitesList translates comma-separated cipher suites list into
// cipher suites list.
func RawCipherSuitesStrToCipherSuitesList(rawCS string) []string {
	csNoSpace := strings.ReplaceAll(rawCS, " ", "")
	if len(csNoSpace) != 0 {
		return strings.Split(csNoSpace, ",")
	}
	return []string{}
}

// CipherSuitesStrToIDs translates comma-separated cipher suites list into
// cipher suites IDs.
func CipherSuitesStrToIDs(rawCS string) ([]uint16, error) {
	csList := RawCipherSuitesStrToCipherSuitesList(rawCS)
	if len(csList) == 0 {
		return []uint16{}, nil
	} else {
		return flag.TLSCipherSuites(csList)
	}
}

// HttpTransportFromCipherSuites translates cipher suites IDs into http.Transport.
func HttpTransportFromCipherSuites(cs []uint16) *http.Transport {
	tlsConfig := &tls.Config{
		CipherSuites: cs,
	}
	return &http.Transport{TLSClientConfig: tlsConfig}
}

func AddCipherSuitesToConfig(c *rest.Config, cs []uint16, caBundle []byte, serverName string) error {
	tlsConfig := new(tls.Config)

	tlsConfig.RootCAs = x509.NewCertPool()
	if ok := tlsConfig.RootCAs.AppendCertsFromPEM(caBundle); !ok {
		return fmt.Errorf("error when append certificates from PEM")
	}
	tlsConfig.ServerName = serverName
	tlsConfig.CipherSuites = cs

	trans := http.Transport{TLSClientConfig: tlsConfig}
	c.Transport = &trans
	return nil
}
