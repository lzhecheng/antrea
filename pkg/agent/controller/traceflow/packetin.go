// Copyright 2020 Antrea Authors
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

package traceflow

import (
	"errors"
	"fmt"
	"time"
	"net"
	
	"k8s.io/klog"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware-tanzu/antrea/pkg/apis/traceflow/v1"
)

func (c *Controller) ReceivePacketIn(stopCh <-chan struct{}) {
	ch := make(chan *ofctrl.PacketIn)
	c.ofClient.SubscribePacketIn(1, ch)

	wait.PollUntil(time.Second, func() (done bool, err error) {
		pktIn := <-ch
		tf, err := c.ParsePacketIn(pktIn)
		klog.Infof("updated crd: %+v", tf)
		c.updateTraceflowCRD(tf, tf.Phase)

		return false, err
	}, stopCh)
}

func (c *Controller) ParsePacketIn(pktIn *ofctrl.PacketIn) (*v1.Traceflow, error) {
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField

	// get cross node tag
	if match = getMatchField(matchers, 9); match == nil {
		return nil, errors.New("traceflow cross node tag not found")
	}
	rngTag := openflow13.NewNXRange(28, 31)
	tag, err := getInfoInReg(matchers, match, rngTag)
	if err != nil {
		return nil, err
	}

	// get CRD
	tf, err := c.GetTraceflowCRD(uint8(tag))
	if err != nil {
		return nil, err
	}

	obs := make([]v1.Observation, 0)
	ifSender := ifSender(uint8(tag), c.senders)
	tableID := pktIn.TableId

	if ifSender {
		ob := new(v1.Observation)
		ob.ComponentType = v1.SPOOFGUARD
		ob.ResourceType = v1.FORWARDED
		ob.NodeUUID = c.nodeConfig.Name
		obs = append(obs, *ob)
	} else {
		ob := new(v1.Observation)
		ob.ComponentType = v1.FORWARDING
		ob.ResourceType = v1.RECEIVED
		ob.NodeUUID = c.nodeConfig.Name
		obs = append(obs, *ob)
	}

	// get drop table
	if tableID == 60 || tableID == 100 {
		ob := new(v1.Observation)
		ob.ResourceType = v1.DROPPED
		ob.ComponentType = v1.DFW
		ob.NodeUUID = c.nodeConfig.Name
		obs = append(obs, *ob)
		tf.Phase = v1.SUCCESS		
	}

	// ingress Rule, DFW
	if match = getMatchField(matchers, 4); match != nil {
		ingress, err := getInfoInReg(matchers, match, nil)
		if err != nil {
			return nil, err
		}
		ob := new(v1.Observation)
		ob.RuleID = fmt.Sprint(ingress)
		ob.ComponentType = v1.DFW
		ob.ResourceType = v1.FORWARDED
		ob.NodeUUID = c.nodeConfig.Name
		obs = append(obs, *ob)
	}

	// egress Rule, DFW
	if match = getMatchField(matchers, 5); match != nil {
		egress, err := getInfoInReg(matchers, match, nil)
		if err != nil {
			return nil, err
		}
		ob := new(v1.Observation)
		ob.RuleID = fmt.Sprint(egress)
		ob.ComponentType = v1.DFW
		ob.ResourceType = v1.FORWARDED
		ob.NodeUUID = c.nodeConfig.Name
		obs = append(obs, *ob)
	}

	// get output table
	if tableID == 110 {
		ob := new(v1.Observation)
		
		if match = getMatchField(matchers, 8); match != nil {
			name, err := getInfoInReg(matchers, match, nil)
			if err != nil {
				return nil, err
			}
			ob.ComponentName = intToIP(name)
			ob.ResourceType = v1.FORWARDED
		} else {
			tf.Phase = v1.SUCCESS
			ob.ResourceType = v1.DELIVERED
		}

		ob.ComponentName = tableIDToComponentName[tableID]
		ob.ComponentType = v1.FORWARDING
		ob.NodeUUID = c.nodeConfig.Name
		obs = append(obs, *ob)
	}
	
	if ifSender {
		tf.NodeSender = obs
	} else {
		tf.NodeReceiver = obs
	}
	return tf, nil
}

func ifSender(tag uint8, senders map[uint8]*v1.Traceflow) bool {
	if _, ok := senders[tag]; ok {
		delete(senders, tag)
		return true
	}
	return false
}

// GetTraceflowCRD returns traceflow CRD with cross node tag.
func (c *Controller) GetTraceflowCRD(tag uint8) (*v1.Traceflow, error) {
	if tf, ok := c.running[tag]; ok {
		return tf, nil
	}
	return nil, errors.New("traceflow with the cross tag node doesn't exist")
}

func intToIP(ip uint32) string {
	result := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		result[i] = byte(ip >> (i * 8))
	}
	return result.String()
}
