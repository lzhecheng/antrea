#!/usr/bin/env bash

# Copyright 2019 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Get sonobouy
mkdir sonobouy && cd sonobouy
wget https://github.com/vmware-tanzu/sonobuoy/releases/download/v0.16.4/sonobuoy_0.16.4_linux_amd64.tar.gz
tar -zxvf sonobuoy_0.16.4_linux_amd64.tar.gz

# Run sonobouy
sonobuoy delete --wait
sonobuoy run --wait --e2e-focus='\[Feature:NetworkPolicy\]'
results=$(sonobuoy retrieve)
sonobuoy results $results
sonobuoy delete --wait

# clean up
cd .. && rm -rf sonobouy