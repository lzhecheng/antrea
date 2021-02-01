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
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/antrea/pkg/apis"
)

type apiserver int

const (
	controller apiserver = apis.AntreaControllerAPIPort
	agent      apiserver = apis.AntreaAgentAPIPort

	cipherSuite    = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 // a TLS1.2 Cipher Suite
	cipherSuiteStr = "ECDHE-RSA-AES128-GCM-SHA256"
)

var (
	cipherSuites             = []uint16{cipherSuite}
	opensslTLS13CipherSuites = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
)

// TestTLSCipherSuites tests Cipher Suite and TLSVersion config on Antrea Apiserver, Controller side or Agent side.
func TestTLSCipherSuites(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	data.configureTLS(t, cipherSuites, "VersionTLS12")

	controllerPod, err := data.getAntreaController()
	assert.NoError(t, err, "failed to get Antrea Controller Pod")
	controllerPodName := controllerPod.Name
	controlPlaneNode := controlPlaneNodeName()
	agentPodName, err := data.getAntreaPodOnNode(controlPlaneNode)
	assert.NoError(t, err, "failed to get Antrea Agent Pod Name on Control Plane Node")

	tests := []struct {
		podName       string
		containerName string
		apiserver     apiserver
		apiserverStr  string
	}{
		{controllerPodName, controllerContainerName, controller, "Controller"},
		{agentPodName, agentContainerName, agent, "Agent"},
	}
	for _, tc := range tests {
		data.checkTLS(t, tc.podName, tc.containerName, tc.apiserver, tc.apiserverStr)
	}
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
		antreaControllerConf = strings.Replace(antreaControllerConf, "#tlsCipherSuites:", fmt.Sprintf("tlsCipherSuites: %s", cipherSuitesStr), 1)
		antreaControllerConf = strings.Replace(antreaControllerConf, "#tlsMinVersion:", fmt.Sprintf("tlsMinVersion: %s", tlsMinVersion), 1)
		data["antrea-controller.conf"] = antreaControllerConf
		antreaAgentConf, _ := data["antrea-agent.conf"]
		antreaAgentConf = strings.Replace(antreaAgentConf, "#tlsCipherSuites:", fmt.Sprintf("tlsCipherSuites: %s", cipherSuitesStr), 1)
		antreaAgentConf = strings.Replace(antreaAgentConf, "#tlsMinVersion:", fmt.Sprintf("tlsMinVersion: %s", tlsMinVersion), 1)
		data["antrea-agent.conf"] = antreaAgentConf
	}, true, true); err != nil {
		t.Fatalf("Failed to enable configure Cipher Suites and TLSMinVersion: %v", err)
	}
}

func (data *TestData) checkTLS(t *testing.T, podName string, containerName string, apiserver apiserver, apiserverStr string) {
	// 1. TLSMaxVersion unset, then a TLS1.3 Cipher Suite should be used.
	stdouts := data.openssl(t, podName, containerName, false, int(apiserver))
	for _, stdout := range stdouts {
		oneTLS13CS := false
		for _, cs := range opensslTLS13CipherSuites {
			if strings.Contains(stdout, fmt.Sprintf("New, TLSv1.3, Cipher is %s", cs)) {
				oneTLS13CS = true
				break
			}
		}
		assert.Equal(t, true, oneTLS13CS,
			"Cipher Suite used by %s Apiserver should be a TLS1.3 one, output: %s", apiserverStr, stdout)
	}

	// 2. Set TLSMaxVersion to TLS1.2, then TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be used
	stdouts = data.openssl(t, podName, containerName, true, int(apiserver))
	for _, stdout := range stdouts {
		assert.Equal(t, true, strings.Contains(stdout, fmt.Sprintf("New, TLSv1.2, Cipher is %s", cipherSuiteStr)),
			"Cipher Suite used by %s Server should be the TLS1.2 one '%s', output: %s", apiserverStr, cipherSuiteStr, stdout)
	}
}

func (data *TestData) openssl(t *testing.T, pod string, container string, tls12 bool, port int) []string {
	var stdouts []string
	tests := []struct {
		enabled bool
		ip      string
		option  string
	}{
		{
			clusterInfo.podV4NetworkCIDR != "",
			"127.0.0.1",
			"-4",
		},
		{
			clusterInfo.podV6NetworkCIDR != "",
			"::",
			"-6",
		},
	}
	for _, tc := range tests {
		if !tc.enabled {
			continue
		}
		cmd := []string{"timeout", "1", "openssl", "s_client", "-connect", net.JoinHostPort(tc.ip, fmt.Sprint(port)), tc.option}
		if tls12 {
			cmd = append(cmd, "-tls1_2")
		}
		stdout, _, _ := data.runCommandFromPod(antreaNamespace, pod, container, cmd)
		t.Logf("Ran '%s' on Pod %s", strings.Join(cmd, " "), pod)
		stdouts = append(stdouts, stdout)
	}
	return stdouts
}
