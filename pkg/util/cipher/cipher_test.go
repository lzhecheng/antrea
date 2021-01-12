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
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/rest"
)

func TestAppendTLSConfig(t *testing.T) {
	config := rest.Config{
		Host:            "http://1.1.1.1:443",
		BearerToken:     "token",
		BearerTokenFile: "/tmp/token-file",
	}
	caBundle := `-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRhbnRy
ZWEtY2FAMTYxMTY0NjczODAeFw0yMTAxMjYwNjM4NTdaFw0yMjAxMjYwNjM4NTda
MBwxGjAYBgNVBAMMEWFudHJlYUAxNjExNjQ2NzM4MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAmF24OvynHRA1VIn9lL9iDM0KhO1CxjoRm7Y/1c5bbaqw
+HkaQKLMGTxItTvoNV4UeotavLo+P1FH2E7fTFdfn8dMoSZXHaPtcTOzDWFPGage
iJI9f//wwS81ft+bkexP0s8C2bW7zP5q+MFmdUqiIYWkIHgNr+E607P4XEEuA1zu
QIyTVWvMyXqMMyQmsmwfikMEUvaWYXdYJA3A/va5di96PFddzplT7c10TgaLO2xV
A3HcRmI/SveNC8oFituLZYNgdFl80v/w8LUUKojCmRSCcnj2XGmAGFx7wNnA6U1/
7Fs8tK26DNXCluKwxbKfvrfHNGEzbDASEEOoBAnCBQIDAQABo4GTMIGQMA4GA1Ud
DwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB8G
A1UdIwQYMBaAFHmTa17VUt1cMIRwYQIC9l0XqfYtMDoGA1UdEQQzMDGCBmFudHJl
YYIWYW50cmVhLmt1YmUtc3lzdGVtLnN2Y4IJbG9jYWxob3N0hwR/AAABMA0GCSqG
SIb3DQEBCwUAA4IBAQB5H1rXfHvevVpO441WlRQ/4xBsHM4a65mLkvfU8agavowJ
cmtYMVHG4kKfs70pL2AQ1Ihb7pwO0kt3k8WkoLCEk9h8p+fXIIWEWtV2B7XG705n
uUU2wq3V0dUMPikm5Cba84MshiTwbAk9rEaAk2lx8q1qas0hHv36styo2U75iNoj
LTAv3m619xptKMl2I289YdB4I8TswTYARNFWkv4jfwzFQS8lPVLDNT52hab+NQAV
HCKn31MdhZgvTRwl0LXq1+VkQAfHei4cFEEyg9y+8uOGER9Ibi6CzEUN7EjfNRUu
X7/QTxqyi1tpU8NEdl48Ie6s1lJNj3AOjs3RJgpJ
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIBATANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRhbnRy
ZWEtY2FAMTYxMTY0NjczODAeFw0yMTAxMjYwNjM4NTdaFw0yMjAxMjYwNjM4NTda
MB8xHTAbBgNVBAMMFGFudHJlYS1jYUAxNjExNjQ2NzM4MIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAwuOLmmSkaKu7GgQePRhhgt5m25IovmEEsVZDksa8
SzqjuevFoOR+QfHK/k8/3DKyM4Vqp9YxDg+GOcBuwX3eD/xiqguufou5rJ2gAinv
5F3c27Bj98mBoBvlsHLrHudHVxMZlTutely+kxXdVf2N/Gx00Duy5w8XeejKq/a/
vyrmsHKOu0VMNKrYs+US/K63t4ROQtIUcdqN7rLhPRjgr/jDuZCUJhgQJW17+Lm6
+xSu7MKUDLdBfodO/7sVwP2FfGPa+CugBPvbylw3D6O5TBqf+/4XmCswIyf7M2IC
zlbcY8Gix4CrowgvT1iY4Nr6enasIYyHxQ6O2F1a5blp4QIDAQABo0IwQDAOBgNV
HQ8BAf8EBAMCAqQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUeZNrXtVS3Vww
hHBhAgL2XRep9i0wDQYJKoZIhvcNAQELBQADggEBAEL62bFwUK6fLzP6zYb0WfZY
RAyuhPZND2wXV9Lc8lsW253kGNY0CmKPRXU7mts0VxJB+0iCPm08Bi1PROmX4uKc
VbO4ZBS8CtZJNC8DBK0TdRWecfmo56lIFYJVPz0AWDU6oZ6HmPhuiZ2mBCIbJykd
HVmsjJ9eMihzlykNEj890jpDfSyPfF3qSzr11/pDZ1vOrVJGih9H6/dVyZ1QdqK9
Z8VwpXnADeT4errNNUdPFDUi98GtGCc4vlHqAgt7pHzBpXlfRy//gby8+ymfwArf
eKBeyc0hPDwTthJZpSco4WntwwtFNUAmOz3qP5F7ESz0DKzLd98K/Q9VRZlIVkM=
-----END CERTIFICATE-----`

	tests := []struct {
		config        *rest.Config
		cipherSuites  string
		tlsMinVersion string
		tlsMaxVersion string
		caBundle      []byte
		serverName    string
	}{
		{&config,
			"TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA",
			"VersionTLS12",
			"VersionTLS13",
			[]byte(caBundle),
			"serverName",
		},
	}
	for _, tc := range tests {
		tlsConfig, err := NewTLSConfig(tc.cipherSuites, tc.tlsMinVersion, tc.tlsMaxVersion)
		assert.NoError(t, err)
		err = AppendTLSConfig(tc.config, tlsConfig, tc.caBundle, tc.serverName)
		assert.NoError(t, err)
	}
}
