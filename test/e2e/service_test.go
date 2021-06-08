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
	// TODO: Support for dual-stack and IPv6-only clusters
	skipIfIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	svcName := "nginx"
	svc, cleanup := data.createClusterIPServiceAllInOne(t, svcName, controlPlaneNodeName())
	defer cleanup()
	t.Logf("%s Service is ready", svcName)

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
	curlSvc(controlPlaneNodeName())
	if winNode != "" {
		t.Logf("Try to curl Cluster IP Service from a Windows host")
		curlSvc(winNode)
	}
}

// TestClusterIPHostAccessOnKind tests traffic from a HostNetwork Pod to Cluster IP Service when provider is Kind.
func TestClusterIPHostAccessOnKind(t *testing.T) {
	skipIfProviderIsNot(t, "kind", "TestClusterIPHostAccess tests on providers other than Kind.")
	// TODO: Support for dual-stack and IPv6-only clusters
	skipIfIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	svcName := "nginx"
	node := controlPlaneNodeName()
	svc, cleanup := data.createClusterIPServiceAllInOne(t, svcName, node)
	defer cleanup()
	t.Logf("%s Service is ready", svcName)

	client := "client"
	require.NoError(t, data.createHostNetworkAgnhostPodOnNode(client, node))
	defer data.deletePod(testNamespace, client)
	_, err = data.podWaitForIPs(defaultTimeout, client, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, client, testNamespace))

	cmd := []string{"curl", fmt.Sprintf("%s:80", svc.Spec.ClusterIP)}
	stdout, stderr, err := data.runCommandFromPod(testNamespace, client, agnhostContainerName, cmd)
	if err != nil {
		t.Errorf("Error when curling from a HostNetwork Pod to Cluster IP Service, stdout: %s, stderr: %s: %v",
			stdout, stderr, err)
	} else {
		t.Logf("curl from a HostNetwork Pod on Node '%s' succeeded\n", node)
	}
}

func (data *TestData) createClusterIPServiceAllInOne(t *testing.T, name string, node string) (*corev1.Service, func()) {
	ipv4Protocol := corev1.IPv4Protocol
	require.NoError(t, data.createNginxPod(name, node))
	_, err := data.podWaitForIPs(defaultTimeout, name, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, name, testNamespace))
	svc, err := data.createNginxClusterIPService(name, false, &ipv4Protocol)
	require.NoError(t, err)

	cleanup := func() {
		data.deletePodAndWait(defaultTimeout, name)
		data.deleteServiceAndWait(defaultTimeout, name)
	}

	return svc, cleanup
}
