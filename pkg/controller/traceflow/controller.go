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
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"

	traceflowv1 "github.com/vmware-tanzu/antrea/pkg/apis/traceflow/v1"
	clientsetversioned "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
)

var minTagNum uint8 = 1
var maxTagNum uint8 = 14

// Controller is for traceflow.
type Controller struct {
	client  clientsetversioned.Interface
	running map[uint8]*traceflowv1.Traceflow
	tags    []uint8
}

// NewTraceflowController creates a new traceflow controller.
func NewTraceflowController(client clientsetversioned.Interface) *Controller {
	running := make(map[uint8]*traceflowv1.Traceflow)
	var tags []uint8
	for i := minTagNum; i < maxTagNum; i++ {
		tags = append(tags, i)
	}
	return &Controller{client, running, tags}
}

// Run creates traceflow controller CRD first after controller is running.
func (controller *Controller) Run(stopCh <-chan struct{}) {
	// Load all cross node tags from CRD into controller's cache.
	list, err := controller.client.AntreaV1().Traceflows().List(v1.ListOptions{})
	if err != nil {
		klog.Errorf("Failed to list all Antrea Traceflows")
	}
	for _, tf := range list.Items {
		if tf.Phase == traceflowv1.RUNNING {
			if err := controller.occupyTag(tf.CrossNodeTag); err != nil {
				klog.Errorf("Load Traceflow's tag failed %v+: %v", tf, err)
			}
			controller.running[tf.CrossNodeTag] = &tf
		}
	}

	klog.Info("Starting Antrea Traceflow Controller")
	wait.PollUntil(time.Second, func() (done bool, err error) {
		list, err := controller.client.AntreaV1().Traceflows().List(v1.ListOptions{})
		if err != nil {
			klog.Errorf("Fail to list all Antrea Traceflows")
			return false, err
		}
		for _, tf := range list.Items {
			switch tf.Phase {
			case traceflowv1.INITIAL:
				if _, err = controller.updateTraceflowCRD(&tf); err != nil {
					klog.Errorf("Update traceflow CRD err: %v", err)
				}
			case traceflowv1.RUNNING:
			default:
				controller.deleteTraceflowCRD(&tf)
			}
		}
		return false, nil
	}, stopCh)
}

func (controller *Controller) updateTraceflowCRD(tf *traceflowv1.Traceflow) (*traceflowv1.Traceflow, error) {
	// validate if the traceflow request meets requirement
	if err := validate(tf); err != nil {
		return nil, err
	}

	// allocate cross node tag
	if tf.CrossNodeTag == 0 {
		tag, err := controller.allocateTag()
		if err != nil {
			return nil, err
		}
		tf.CrossNodeTag = tag
	}

	return controller.client.AntreaV1().Traceflows().Update(tf)
}

func (controller *Controller) deleteTraceflowCRD(tf *traceflowv1.Traceflow) error {
	controller.deallocateTag(tf.CrossNodeTag)
	delete(controller.running, tf.CrossNodeTag)
	return controller.client.AntreaV1().Traceflows().Delete(tf.ObjectMeta.Name, &v1.DeleteOptions{})
}

func validate(tf *traceflowv1.Traceflow) error {
	if len(tf.SrcNamespace) == 0 && len(tf.SrcPod) == 0 {
		return errors.New("source pod info must be provided")
	}
	if len(tf.DstPod) != 0 && len(tf.DstService) != 0 {
		return errors.New("destination pod and service cannot be both set")
	}
	if len(tf.DstPod) == 0 && len(tf.DstService) == 0 {
		return errors.New("destination pod and service cannot be both not set")
	}
	return nil
}

func (controller *Controller) occupyTag(tag uint8) error {
	if tag < minTagNum || tag > maxTagNum {
		return errors.New("This Traceflow CRD's cross node tag is out of range")
	}

	idx := 0
	for k, v := range controller.tags {
		if v == tag {
			idx = k
			break
		}
	}
	if idx == 0 {
		return errors.New("This Traceflow's CRD cross node tag is already taken")
	}

	controller.tags[idx], controller.tags[len(controller.tags)-1] = controller.tags[len(controller.tags)-1], controller.tags[idx]
	controller.tags = controller.tags[:len(controller.tags)-1]
	return nil
}

func (controller *Controller) allocateTag() (uint8, error) {
	if len(controller.tags) == 0 {
		return 0, errors.New("Too much traceflow now")
	}
	tag := controller.tags[len(controller.tags)-1]
	controller.tags = controller.tags[:len(controller.tags)-1]
	return tag, nil
}

func (controller *Controller) deallocateTag(tag uint8) {
	controller.tags = append(controller.tags, tag)
}
