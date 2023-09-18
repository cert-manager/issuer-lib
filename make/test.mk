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

# The cert-manager CRDs are needed in integration tests, where they are loaded
# into Kubernetes API server managed by controller-runtime envtest.
CERT_MANAGER_CRDS := $(BINDIR)/scratch/cert-manager.crds.yaml
$(CERT_MANAGER_CRDS):
	mkdir -p $(dir $@)
	curl https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.crds.yaml \
		 -fsSL -o $@

$(BINDIR)/envs/CERT_MANAGER_CRDS: $(CERT_MANAGER_CRDS) | $(BINDIR)/envs
	@echo "$(PWD)/$(CERT_MANAGER_CRDS)" > $@

$(BINDIR)/envs/SIMPLE_CRDS: generate-manifests | $(BINDIR)/envs
	@echo "$(PWD)/internal/testsetups/simple/deploy/crds" > $@

$(BINDIR)/envs/KUBEBUILDER_ASSETS: | $(BINDIR)/envs $(NEEDS_KUBECTL) $(NEEDS_ETCD) $(NEEDS_KUBE-APISERVER)
	@echo "$(PWD)/$(BINDIR)/tools" > $@

test-envs: $(BINDIR)/envs/CERT_MANAGER_CRDS
test-envs: $(BINDIR)/envs/SIMPLE_CRDS
test-envs: $(BINDIR)/envs/KUBEBUILDER_ASSETS
test-envs: FORCE
	@echo "SETTING test environment variables"
	@$(eval export TEST_MODE=$(TEST_MODE))

$(BINDIR)/envs/KUBECONFIG: $(KIND_KUBECONFIG) | $(BINDIR)/envs
	@echo "$(PWD)/$(KIND_KUBECONFIG)" > $@

test-e2e-envs: test-envs
test-e2e-envs: $(BINDIR)/envs/KUBECONFIG
test-e2e-envs: FORCE

$(BINDIR)/envs:
	@mkdir -p $@
