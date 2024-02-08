# Copyright 2023 The cert-manager Authors.
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

.PHONY: generate-crds-test-unit
## Generate Unit test CRD manifests.
## @category [shared] Generate/ Verify
generate-crds-test-unit: | $(NEEDS_CONTROLLER-GEN) $(NEEDS_YQ)
	$(CONTROLLER-GEN) crd \
		paths=./internal/testapi/api/... \
		output:crd:artifacts:config=./internal/testapi/crds

shared_generate_targets += generate-crds-test-unit

.PHONY: test-unit
## Unit tests
## @category Testing
test-unit: | $(cert_manager_crds) $(NEEDS_GOTESTSUM) $(NEEDS_ETCD) $(NEEDS_KUBE-APISERVER) $(NEEDS_KUBECTL) $(ARTIFACTS)
	CERT_MANAGER_CRDS=$(CURDIR)/$(cert_manager_crds) \
	SIMPLE_CRDS=$(CURDIR)/internal/testapi/crds \
	KUBEBUILDER_ASSETS=$(CURDIR)/$(bin_dir)/tools \
	$(GOTESTSUM) \
		--junitfile=$(ARTIFACTS)/junit-go-e2e.xml \
		-- \
		-coverprofile=$(ARTIFACTS)/filtered.cov \
		./... \
		-- \
		-ldflags $(go_manager_ldflags)
