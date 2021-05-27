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
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// TestClusterIPHostAccess tests traffic from host to ClusterIP Service.
func TestClusterIPHostAccess(t *testing.T) {
	// TODO: Support for dual-stack and IPv6-only clusters
	skipIfIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	svcName := "nginx"
	node := nodeName(0)
	svc, cleanup := data.createClusterIPServiceAndBackendPods(t, svcName, node)
	defer cleanup()
	t.Logf("%s Service is ready", svcName)

	var linNode, winNode string
	linNode = node
	t.Logf("Picked Linux Node: %s", linNode)
	if len(clusterInfo.windowsNodes) != 0 {
		idx := clusterInfo.windowsNodes[0]
		winNode = clusterInfo.nodes[idx].name
		t.Logf("Picked Windows Node: %s", winNode)

		antreaProxy, err := data.GetAntreaProxyStatus()
		if err != nil {
			t.Errorf("Failed to get antrea-proxy is enabled or not")
		}
		if antreaProxy {
			getGWCmd := fmt.Sprintf("powershell \"Get-NetIPAddress -InterfaceAlias antrea-gw0 -AddressFamily IPv4 | Select-Object -Property IPAddress | Format-Table -HideTableHeaders\"")
			getGWRc, getGWStdout, getGWStderr, err := RunCommandOnNode(winNode, getGWCmd)
			if getGWRc != 0 || err != nil {
				t.Fatalf("Error when running command '%s' on Node '%s', rc: %d, stdout: %s, stderr: %s, error: %v",
					getGWCmd, winNode, getGWRc, getGWStdout, getGWStderr, err)
			}
			var gwIP, printStdout string
			if err := wait.PollImmediate(defaultInterval, defaultTimeout, func() (added bool, err error) {
				printCmd := fmt.Sprintf("powershell \"route print | grep %s\"", svc.Spec.ClusterIP)
				printRc, printStdout, printStderr, err := RunCommandOnNode(winNode, printCmd)
				if printRc != 0 || err != nil {
					printErr := fmt.Errorf("error when running command '%s' on Node '%s', rc: %d, stdout: %s, stderr: %s, error: %v",
						printCmd, winNode, printRc, printStdout, printStderr, err)
					return false, printErr
				}
				gwIP = strings.TrimSpace(getGWStdout)
				r := regexp.MustCompile(fmt.Sprintf("%s +255.255.255.255 +On-link +%s +65", svc.Spec.ClusterIP, gwIP))
				if !r.MatchString(printStdout) {
					return false, nil
				}
				return true, nil
			}); err == wait.ErrWaitTimeout {
				t.Fatalf("With antrea-proxy enabled, antrea-gw '%s', host route is not as expected, stdout: %s", gwIP, printStdout)
			} else if err != nil {
				t.Fatalf("With antrea-proxy enabled, antrea-gw '%s', host route is not as expected: %v", gwIP, err)
			} else {
				t.Logf("Expected host route is found")
			}
		}
	}

	curlSvc := func(node string) {
		// Retry is needed for rules to be installed by kube-proxy/antrea-proxy.
		cmd := fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s:80", svc.Spec.ClusterIP)
		rc, stdout, stderr, err := RunCommandOnNode(node, cmd)
		if rc != 0 || err != nil {
			t.Errorf("Error when running command '%s' on Node '%s', rc: %d, stdout: %s, stderr: %s, error: %v",
				cmd, node, rc, stdout, stderr, err)
		} else {
			t.Logf("curl from Node '%s' succeeded", node)
		}
	}
	t.Logf("Try to curl ClusterIP Service from a Linux host")
	curlSvc(linNode)
	if winNode != "" {
		t.Logf("Try to curl Cluster IP Service from a Windows host")
		curlSvc(winNode)
	}
}

func (data *TestData) createClusterIPServiceAndBackendPods(t *testing.T, name string, node string) (*corev1.Service, func()) {
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
