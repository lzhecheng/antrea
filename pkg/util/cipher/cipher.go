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
	"net/http"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/component-base/cli/flag"
)

var tlsVersionMap = map[string]uint16{
	"VersionTLS10": tls.VersionTLS10,
	"VersionTLS11": tls.VersionTLS11,
	"VersionTLS12": tls.VersionTLS12,
	"VersionTLS13": tls.VersionTLS13,
}

// NewTLSConfig generates a tls.Config with given cipher suites string, TLS min version and TLS max version.
func NewTLSConfig(cipherSuites string, minVersion string, maxVersion string) (*tls.Config, error) {
	csStrList := strings.Split(strings.ReplaceAll(cipherSuites, " ", ""), ",")
	csIntList, err := flag.TLSCipherSuites(csStrList)
	if err != nil {
		return nil, err
	}
	// #nosec G402: ignore MinVersion and MaxVersion options in test code
	return &tls.Config{
		CipherSuites: csIntList,
		MinVersion:   tlsVersionMap[minVersion],
		MaxVersion:   tlsVersionMap[maxVersion],
	}, nil
}

// AppendTLSConfig appends TLS config (Cipher Suites, TLSVersion, PreferServerCipherSuites, caBundle, serverName) to
// *rest.Config.
func AppendTLSConfig(c *rest.Config, cipherTLSConfig *tls.Config, caBundle []byte, serverName string) error {
	tlsConfig := new(tls.Config)
	tlsConfig.RootCAs = x509.NewCertPool()
	if ok := tlsConfig.RootCAs.AppendCertsFromPEM(caBundle); !ok {
		return fmt.Errorf("error appending certificates from PEM encoded certificate")
	}
	tlsConfig.ServerName = serverName
	tlsConfig.CipherSuites = cipherTLSConfig.CipherSuites
	tlsConfig.MinVersion = cipherTLSConfig.MinVersion
	tlsConfig.MaxVersion = cipherTLSConfig.MaxVersion
	tlsConfig.PreferServerCipherSuites = false

	trans := http.Transport{TLSClientConfig: tlsConfig}
	c.Transport = &trans
	return nil
}
