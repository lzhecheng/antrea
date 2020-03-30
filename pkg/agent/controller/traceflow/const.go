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

var tableIDToComponentName map[uint8]string = map[uint8]string{
	0:   "Classifier",
	10:  "SpoofGuard",
	20:  "ARP",
	30:  "Conntrack",
	31:  "Conntrack State",
	40:  "DNAT",
	50:  "Egress Rule",
	60:  "Egress Drop",
	70:  "L3 Forwarding",
	80:  "L2 Calculation",
	90:  "Ingress Rule",
	100: "Ingress Drop",
	105: "Conntrack Commit",
	110: "L2 Forwarding Ouput",
}

var tableIDToObIdx map[uint8]uint32 = map[uint8]uint32{
	60:  0,
	100: 1,
	110: 2,
}
