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

package cases

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
	promv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/test/scale/types"
	"github.com/vmware-tanzu/antrea/test/scale/utils"
)

var (
	networkPolicyLabelKey = "antrea-scale-test-netpol"
)

// Total NetworkPolicies number = 50% Pods number
//  5% NetworkPolicies cover 80% Pods = 2.5% Pods number
// 15% NetworkPolicies cover 13% Pods = 7.5% Pods number
// 80% NetworkPolicies cover 6% Pods  = 40%  Pods number
func generateNetpolTemplate(labelNum int, podName string, isIngress bool) *netv1.NetworkPolicy {
	name := uuid.New().String()
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt(80)
	policyPorts := []netv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port}}
	policyPeer := []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": podName}}}}
	netpol := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: types.ScaleTestNamespace,
			Labels:    map[string]string{networkPolicyLabelKey: ""},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: types.PickLabels(labelNum, false)},
		},
	}
	if isIngress {
		netpol.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeIngress}
		netpol.Spec.Ingress = []netv1.NetworkPolicyIngressRule{{Ports: policyPorts, From: policyPeer}}
	} else {
		netpol.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeEgress}
		netpol.Spec.Egress = []netv1.NetworkPolicyEgressRule{{Ports: policyPorts, To: policyPeer}}
	}
	return netpol
}

func generateP80NetworkPolicies(podName string) *netv1.NetworkPolicy {
	return generateNetpolTemplate(1, podName, rand.Int()%2 == 0)
}
func generateP15NetworkPolicies(podName string) *netv1.NetworkPolicy {
	return generateNetpolTemplate(7, podName, rand.Int()%2 == 0)
}
func generateP5NetworkPolicies(podName string) *netv1.NetworkPolicy {
	return generateNetpolTemplate(10, podName, rand.Int()%2 == 0)
}

func generateNetworkPolicies(data TestData) ([]*netv1.NetworkPolicy, error) {
	p5 := data.BluePrint().PodNumber() * 25 / 1000   // 2.5%
	p15 := data.BluePrint().PodNumber() * 75 / 1000  // 7.5%
	p80 := data.BluePrint().PodNumber() * 400 / 1000 // 40%
	var result []*netv1.NetworkPolicy
	podList, err := data.KubernetesClientSet().
		CoreV1().Pods(types.ScaleTestNamespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	rand.Shuffle(len(podList.Items), func(i, j int) { podList.Items[i], podList.Items[j] = podList.Items[j], podList.Items[i] })
	items := podList.Items[:p5+p15+p80]
	for i := 0; i < p5; i++ {
		result = append(result, generateP80NetworkPolicies(items[i].Name))
	}
	for i := 0; i < p15; i++ {
		result = append(result, generateP15NetworkPolicies(items[i].Name))
	}
	for i := 0; i < p80; i++ {
		result = append(result, generateP5NetworkPolicies(items[i].Name))
	}
	return result, nil
}

func TestCaseNetworkPolicyRealization() TestCase {
	var startProcessedNumber int
	var npNum int
	var nps []*netv1.NetworkPolicy
	return repeat("Repeat", 3,
		chain("NetworkPolicy process test",
			do("Record number of processed NetworkPolicies in Antrea controller before running", func(ctx Context, data TestData) error {
				return wait.PollUntil(time.Second, func() (bool, error) {
					promAPI := promv1.NewAPI(data.PrometheusClient())
					err := utils.DefaultRetry(func() error {
						result, _, err := promAPI.Query(ctx, "antrea_controller_network_policy_processed", time.Now())
						if err != nil {
							klog.Warningf("Failed to retrieve antrea_controller_network_policy_processed: %v", err)
							return err
						}
						samples := result.(model.Vector) // Expected that there should only be one instance.
						if len(samples) == 0 {
							return fmt.Errorf("can not retrieve valid metric data")
						}
						startProcessedNumber = int(samples[0].Value)
						return nil
					})
					if err != nil {
						return false, err
					}
					return true, nil
				}, ctx.Done())
			}),
			fan("Adding NetworkPolicies and wait them to be processed",
				do("Adding NetworkPolicies", func(ctx Context, data TestData) error {
					var err error
					nps, err = generateNetworkPolicies(data)
					if err != nil {
						return fmt.Errorf("error when generating network policies: %w", err)
					}
					npNum = len(nps)
					klog.Infof("Going to process %d NetworkPolicies", npNum)
					for _, netpol := range nps {
						if err := utils.DefaultRetry(func() error {
							_, err := data.KubernetesClientSet().
								NetworkingV1().
								NetworkPolicies(types.ScaleTestNamespace).
								Create(ctx, netpol, metav1.CreateOptions{})
							return err
						}); err != nil {
							return err
						}
					}
					return nil
				}),
				do("Waiting all NetworkPolicies to be processed", func(ctx Context, data TestData) error {
					promAPI := promv1.NewAPI(data.PrometheusClient())
					return wait.PollImmediateUntil(time.Second, func() (bool, error) {
						var processed int
						err := utils.DefaultRetry(func() error {
							result, _, err := promAPI.Query(ctx, "antrea_controller_network_policy_processed", time.Now())
							if err != nil {
								return err
							}
							samples := result.(model.Vector) // At current time, we expect that there is only one instance.
							processed = int(samples[0].Value)
							return nil
						})
						if err != nil {
							return false, err
						}
						return processed-startProcessedNumber >= npNum, nil
					}, ctx.Done())
				}),
			),
			do("Check isolation of NetworkPolicies", func(ctx Context, data TestData) error {
				for _, np := range nps {
					klog.Infof("Checking isolation of the NetworkPolicy %s", np.Name)
					podSelector := make(map[string]string)
					for k, v := range np.Spec.PodSelector.MatchLabels {
						podSelector[k] = v
					}
					podSelector[types.PodOnRealNodeLabelKey] = ""
					podList, err := data.KubernetesClientSet().CoreV1().
						Pods(types.ScaleTestNamespace).
						List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&np.Spec.PodSelector)})
					if err != nil {
						return fmt.Errorf("error when selecting networkpolicy applied to pods: %w", err)
					}
					if len(podList.Items) == 0 {
						klog.Infof("No Pod is selected by the NetworkPolicy %s, skip", np.Name)
					}
					var fromPods []corev1.Pod
					var toPods []corev1.Pod
					if len(np.Spec.Ingress) > 0 {
						fromPods = data.TestClientPods()
						toPods = podList.Items
					} else if len(np.Spec.Egress) > 0 {
						fromPods = podList.Items
						toPods = data.TestClientPods()
					}
					for _, fromPod := range fromPods {
						gErr, _ := errgroup.WithContext(context.Background())
						for _, toPod := range toPods {
							gErr.Go(func() error {
								return utils.DefaultRetry(func() error {
									exec, err := remotecommand.NewSPDYExecutor(data.Kubeconfig(), "POST", execURL(&fromPod, data.KubernetesClientSet(), toPod.Status.PodIP))
									if err != nil {
										return fmt.Errorf("error when creating SPDY executor: %w", err)
									}
									var stdout, stderr bytes.Buffer
									if err := exec.Stream(remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err == nil {
										return fmt.Errorf("the connection should not be success")
									} else if !strings.Contains(strings.ToLower(stderr.String()), "timed out") {
										return fmt.Errorf("the connection not met timed out error, stdout: `%s`, stderr: `%s`, err: %s", stdout.String(), stderr.String(), err)
									}
									return nil
								})
							})
						}
						if err := gErr.Wait(); err != nil {
							return err
						}
					}
				}
				return nil
			}),
			do("Check connectivity of NetworkPolicies", func(ctx Context, data TestData) error {
				for _, np := range nps {
					klog.Infof("Checking connectivity of the NetworkPolicy %s", np.Name)
					podSelector := make(map[string]string)
					for k, v := range np.Spec.PodSelector.MatchLabels {
						podSelector[k] = v
					}
					podSelector[types.PodOnRealNodeLabelKey] = ""
					podList, err := data.KubernetesClientSet().CoreV1().
						Pods(types.ScaleTestNamespace).
						List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&np.Spec.PodSelector)})
					if err != nil {
						return fmt.Errorf("error when selecting networkpolicy applied to pods: %w", err)
					}
					if len(podList.Items) == 0 {
						klog.Infof("No Pod is selected by the NetworkPolicy %s, skip", np.Name)
					}
					var fromPods []corev1.Pod
					var toPods []corev1.Pod
					if len(np.Spec.Ingress) > 0 {
						if err := utils.DefaultRetry(func() error {
							fromPodsList, err := data.KubernetesClientSet().CoreV1().
								Pods(types.ScaleTestNamespace).
								List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(np.Spec.Ingress[0].From[0].PodSelector)})
							if err != nil {
								return err
							}
							fromPods = fromPodsList.Items
							return nil
						}); err != nil {
							return fmt.Errorf("error when retrieving Pods: %w", err)
						}
						toPods = podList.Items
					} else if len(np.Spec.Egress) > 0 {
						fromPods = podList.Items
						if err := utils.DefaultRetry(func() error {
							fromPodsList, err := data.KubernetesClientSet().CoreV1().
								Pods(types.ScaleTestNamespace).
								List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(np.Spec.Egress[0].To[0].PodSelector)})
							if err != nil {
								return err
							}
							toPods = fromPodsList.Items
							return nil
						}); err != nil {
							return fmt.Errorf("error when retrieving Pods: %w", err)
						}
					}
					for _, fromPod := range fromPods {
						for _, toPod := range toPods {
							if toPod.Status.PodIP == "" {
								klog.Error("Pod %s:%s does not have a valid IP", toPod.Namespace, toPod.Name)
								continue
							}
							exec, err := remotecommand.NewSPDYExecutor(data.Kubeconfig(), "POST", execURL(&fromPod, data.KubernetesClientSet(), toPod.Status.PodIP))
							if err != nil {
								return fmt.Errorf("error when creating SPDY executor: %w", err)
							}
							var stdout, stderr bytes.Buffer
							if err := exec.Stream(remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
								return fmt.Errorf("the connection should be success: %w", err)
							}
						}
					}
				}
				return nil
			}),
			do("Deleting all NetworkPolicies", func(ctx Context, data TestData) error {
				return data.KubernetesClientSet().NetworkingV1().
					NetworkPolicies(metav1.NamespaceDefault).
					DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "purpose=antrea-scale-test-netpol"})
			}),
		))
}
