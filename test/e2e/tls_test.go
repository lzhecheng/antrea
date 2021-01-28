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

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// #nosec G101: false positive triggered by variable name which includes "token"
const tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
const cipherSuite = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 // a TLS1.2 Cipher Suite

var cipherSuites = []uint16{cipherSuite}

// TestTLSCipherSuitesClient tests Cipher Suite and TLSVersion config on Antrea Apiserver.
func TestTLSCipherSuitesAntrea(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	data.configureTLS(t, cipherSuites, "VersionTLS12")
	tls13CipherSuites := make(map[uint16]bool)
	for _, cs := range tls.CipherSuites() {
		if len(cs.SupportedVersions) == 1 && cs.SupportedVersions[0] == tls.VersionTLS13 {
			tls13CipherSuites[cs.ID] = true
		}
	}

	svc, err := data.clientset.CoreV1().Services(antreaNamespace).Get(context.TODO(), "antrea", metav1.GetOptions{})
	assert.NoError(t, err, "failed to get Antrea Service")
	if len(svc.Spec.Ports) == 0 {
		t.Fatal("Antrea Service has no ports")
	}
	url := fmt.Sprintf("https://%s:%d", svc.Spec.ClusterIP, svc.Spec.Ports[0].Port)

	// 1. TLSMaxVersion unset, then a TLS1.3 Cipher Suite should be used.
	respCipherSuite := request(t, url, 0)
	assert.Equal(t, true, tls13CipherSuites[respCipherSuite],
		"Cipher Suite used by Server should be a TLS1.3 one, actual: %s", respCipherSuite)
	// 2. Set TLSMaxVersion to TLS1.2, then TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be used
	respCipherSuite = request(t, url, tls.VersionTLS12)
	assert.Equal(t, cipherSuite, respCipherSuite, "Cipher Suite used by Server should be the TLS1.2 one we set")
}

func (data *TestData) configureTLS(t *testing.T, cipherSuites []uint16, tlsMinVersion string) {
	var cipherSuitesStr string
	if len(cipherSuites) > 0 {
		for i, cs := range cipherSuites {
			cipherSuitesStr = fmt.Sprintf("%s%s", cipherSuitesStr, tls.CipherSuiteName(cs))
			if i != len(cipherSuites)-1 {
				cipherSuitesStr = fmt.Sprintf("%s,", cipherSuitesStr)
			}
		}
	}

	if err := data.mutateAntreaConfigMap(func(data map[string]string) {
		antreaControllerConf, _ := data["antrea-controller.conf"]
		antreaControllerConf = strings.Replace(antreaControllerConf, "#cipherSuites:", fmt.Sprintf("cipherSuites: %s", cipherSuitesStr), 1)
		antreaControllerConf = strings.Replace(antreaControllerConf, "#tlsMinVersion:", fmt.Sprintf("tlsMinVersion: %s", tlsMinVersion), 1)
		data["antrea-controller.conf"] = antreaControllerConf
		antreaAgentConf, _ := data["antrea-agent.conf"]
		antreaAgentConf = strings.Replace(antreaAgentConf, "#cipherSuites:", fmt.Sprintf("cipherSuites: %s", cipherSuitesStr), 1)
		antreaAgentConf = strings.Replace(antreaAgentConf, "#tlsMinVersion:", fmt.Sprintf("tlsMinVersion: %s", tlsMinVersion), 1)
		data["antrea-agent.conf"] = antreaAgentConf
	}, true, true); err != nil {
		t.Fatalf("Failed to enable configure Cipher Suites and TLSMinVersion: %v", err)
	}
}

func request(t *testing.T, url string, tlsMaxVersion uint16) uint16 {
	// #nosec G402: ignore insecure options in test code
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	if tlsMaxVersion > 0 {
		config.MaxVersion = tlsMaxVersion
	}
	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err, "failed to create HTTP request")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokenFile))
	resp, err := client.Do(req)
	assert.NoError(t, err, "failed to connect to %s", url)
	respCipherSuite := resp.TLS.CipherSuite
	defer resp.Body.Close()

	return respCipherSuite
}

// TestTLSCipherSuitesAgent tests Cipher Suite and TLSVersion config on Antrea Agent Apiserver.
func TestTLSCipherSuitesAgent(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	data.configureTLS(t, cipherSuites, "VersionTLS12")
	tls13CipherSuites := make(map[uint16]bool)
	for _, cs := range tls.CipherSuites() {
		if len(cs.SupportedVersions) == 1 && cs.SupportedVersions[0] == tls.VersionTLS13 {
			tls13CipherSuites[cs.ID] = true
		}
	}

	masterNode := nodeName(0)
	podName, err := data.getAntreaPodOnNode(masterNode)
	assert.NoError(t, err, "error when getting Antrea Agent Pod on Master Node")
	curlTLS13CipherSuites := []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}

	// 1. TLSMaxVersion unset, then a TLS1.3 Cipher Suite should be used.
	stdout := data.openssl(podName, false)
	oneTLS13CS := false
	for _, cs := range curlTLS13CipherSuites {
		if strings.Contains(stdout, fmt.Sprintf("New, TLSv1.3, Cipher is %s", cs)) {
			oneTLS13CS = true
			break
		}
	}
	assert.Equal(t, true, oneTLS13CS, "Cipher Suite used by Server should be a TLS1.3 one, output: %s", stdout)

	// 2. Set TLSMaxVersion to TLS1.2, then TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be used
	stdout = data.openssl(podName, true)
	assert.Equal(t, true, strings.Contains(stdout, "New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256"),
		"Cipher Suite used by Server should be the TLS1.2 one we set")
}

func (data *TestData) openssl(podName string, tls12 bool) string {
	cmd := []string{"timeout", "1", "openssl", "s_client", "-connect", "127.0.0.1:10350"}
	if tls12 {
		cmd = append(cmd, "-tls1_2")
	}
	stdout, _, _ := data.runCommandFromPod(antreaNamespace, podName, agentContainerName, cmd)
	return stdout
}
