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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// TestClusterIPHostAccess tests traffic from host to Cluster IP Service.
func TestClusterIPHostAccess(t *testing.T) {
	skipIfProviderIs(t, "kind", "Skipping Kind provider for now.")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfNumNodesLessThan(t, 2)
	// TODO: Support for dual-stack and IPv6-only clusters
	skipIfIPv6Cluster(t)

	ipv4Protocol := corev1.IPv4Protocol
	epNode := nodeName(1)
	nginx := "nginx"
	require.NoError(t, data.createNginxPod(nginx, epNode))
	_, err = data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	defer data.deletePodAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, nginx, testNamespace))
	svc, err := data.createNginxClusterIPService(nginx, false, &ipv4Protocol)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	t.Log("Nginx Service is ready")

	var winNode string
	if len(clusterInfo.windowsNodes) != 0 {
		idx := clusterInfo.windowsNodes[0]
		winNode = clusterInfo.nodes[idx].name
	}

	curlSvc := func(node string) {
		rc, stdout, stderr, err := RunCommandOnNode(node, fmt.Sprintf("curl %s:80", svc.Spec.ClusterIP))
		if rc != 0 || err != nil {
			t.Errorf("Error when running command on Node '%s', rc: %d, stdout: %s, stderr: %s, error: %v",
				node, rc, stdout, stderr, err)
		} else {
			t.Logf("curl from Node '%s' succeeded\n", node)
		}
	}
	t.Logf("Try to curl Cluster IP Service from a Linux host")
	curlSvc(clusterInfo.controlPlaneNodeName)
	if winNode != "" {
		t.Logf("Try to curl Cluster IP Service from a Windows host")
		curlSvc(winNode)
	}
}
