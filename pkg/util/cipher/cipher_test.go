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
	"k8s.io/client-go/rest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCipherSuitesStrToIDs(t *testing.T) {
	tests := []struct {
		str     string
		ids     []uint16
		success bool
	}{
		{"TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA", []uint16{0x0005, 0x000a}, true},
		{" TLS_RSA_WITH_RC4_128_SHA,   TLS_RSA_WITH_3DES_EDE_CBC_SHA ", []uint16{0x0005, 0x000a}, true},
		{"TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA1234", []uint16{}, false},
	}

	for _, tc := range tests {
		output, err := CipherSuitesStrToIDs(tc.str)
		if tc.success {
			assert.NoError(t, err)
			assert.Equal(t, tc.ids, output)
		} else {
			assert.Error(t, err)
		}
	}
}

func TestAddCipherSuitesToConfig(t *testing.T) {
	rawConfig := rest.Config{
		Host: "http://1.1.1.1:80",
		TLSClientConfig: rest.TLSClientConfig{
			CAData:     []byte("ca-data"),
			ServerName: "serverName",
		},
		BearerToken:     "token",
		BearerTokenFile: "token-file",
	}
	expected := rest.Config{}

	tests := []struct {
		rawConfig    *rest.Config
		cipherSuites []uint16
		expected     *rest.Config
	}{
		{&rawConfig, []uint16{0, 1}, &expected},
	}
	for _, tc := range tests {
		o, err := AddCipherSuitesToConfig(tc.rawConfig, tc.cipherSuites)
		if err != nil {
			t.Errorf("error: %v", err)
		} else {
			assert.Equal(t, *tc.expected, *o)
		}
	}
}
