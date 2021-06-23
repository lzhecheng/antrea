// +build windows
// package openflow is needed by antctl which is compiled for macOS too.

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

package openflow

import (
	"fmt"
	"net"

	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/route"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

var globalVirtualSVCMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:fe")

func (c *client) InstallBridgeUplinkFlows() error {
	flows := c.hostBridgeUplinkFlows(*c.nodeConfig.PodIPv4CIDR, cookie.Default)
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.hostNetworkingFlows = flows
	return nil
}

func (c *client) InstallLoadBalancerServiceFromOutsideFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	var flows []binding.Flow
	flows = append(flows, c.loadBalancerServiceFromOutsideFlow(svcIP, svcPort, protocol))
	cacheKey := fmt.Sprintf("L%s%s%x", svcIP, protocol, svcPort)
	return c.addFlows(c.serviceFlowCache, cacheKey, flows)
}

func (c *client) UninstallLoadBalancerServiceFromOutsideFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	cacheKey := fmt.Sprintf("L%s%s%x", svcIP, protocol, svcPort)
	return c.deleteFlows(c.serviceFlowCache, cacheKey)
}

func (c *client) InstallServiceFlows(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	var flows []binding.Flow
	flows = append(flows, c.serviceLBFlow(groupID, svcIP, svcPort, protocol, affinityTimeout != 0))
	if affinityTimeout != 0 {
		flows = append(flows, c.serviceLearnFlow(groupID, svcIP, svcPort, protocol, affinityTimeout))
	}

	gwConfig := c.nodeConfig.GatewayConfig
	flows = append(flows, c.arpResponderFlow(route.GlobalVirtualGWIP, globalVirtualSVCMAC, priorityHigh, cookie.Service))
	if gwConfig.IPv4 != nil {
		flows = append(flows, c.clusterIPHostNetworkFlows(gwConfig.IPv4, cookie.Service)...)
	}
	if gwConfig.IPv6 != nil {
		flows = append(flows, c.clusterIPHostNetworkFlows(gwConfig.IPv6, cookie.Service)...)
	}
	cacheKey := generateServicePortFlowCacheKey(svcIP, svcPort, protocol)
	return c.addFlows(c.serviceFlowCache, cacheKey, flows)
}
