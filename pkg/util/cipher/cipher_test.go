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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateCipherSuitesList(t *testing.T) {
	tests := []struct {
		str     string
		ids     []uint16
		success bool
	}{
		{"TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA", []uint16{0x0005, 0x000a}, true},
		{" TLS_RSA_WITH_RC4_128_SHA,   TLS_RSA_WITH_3DES_EDE_CBC_SHA ", []uint16{0x0005, 0x000a}, true},
		{"TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA1234", []uint16{}, false},
		{" ", []uint16{}, true},
	}

	for _, tc := range tests {
		output, err := GenerateCipherSuitesList(tc.str)
		if tc.success {
			assert.NoError(t, err)
			assert.Equal(t, tc.ids, output)
		} else {
			assert.Error(t, err)
		}
	}
}
