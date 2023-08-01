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

##@ E2E testing

KIND_CLUSTER_NAME ?= issuer-lib-kind
ARTIFACTS := $(BINDIR)/artifacts
KIND_KUBECONFIG := $(BINDIR)/scratch/kube.config

$(BINDIR)/scratch/kind_cluster.yaml: make/config/kind/cluster.yaml | images $(BINDIR)/scratch
	cat $< | \
	sed -e 's|{{KIND_IMAGES}}|$(PWD)/$(IMAGES_TAR_DIR)|g' \
	> $@

$(BINDIR)/scratch/cluster-check: FORCE | $(NEEDS_KIND) $(BINDIR)/scratch
	@if ! $(KIND) get clusters -q | grep -q "^$(KIND_CLUSTER_NAME)\$$"; then \
		echo "❌  cluster $(KIND_CLUSTER_NAME) not found. Starting ..."; \
		echo "trigger" > $@; \
	else \
		echo "✅  existing cluster $(KIND_CLUSTER_NAME) found"; \
	fi

$(KIND_KUBECONFIG): $(BINDIR)/scratch/kind_cluster.yaml $(BINDIR)/scratch/cluster-check | images $(BINDIR)/scratch $(NEEDS_KIND) $(NEEDS_KUBECTL)
	@[ -f "$(BINDIR)/scratch/cluster-check" ] && ( \
		$(KIND) delete cluster --name $(KIND_CLUSTER_NAME); \
		$(CTR) load -i $(docker.io/kindest/node.TAR); \
		$(KIND) create cluster \
			--image $(docker.io/kindest/node.FULL) \
			--name $(KIND_CLUSTER_NAME) \
			--config "$<"; \
		$(CTR) exec $(KIND_CLUSTER_NAME)-control-plane find /mounted_images/ -name "*.tar" -exec echo {} \; -exec ctr --namespace=k8s.io images import --all-platforms --no-unpack --digests {} \; ; \
		$(KUBECTL) config use-context kind-$(KIND_CLUSTER_NAME); \
	) || true

	$(KIND) get kubeconfig --name $(KIND_CLUSTER_NAME) > $@

.PHONY: kind-cluster
kind-cluster: ## Create Kind cluster and wait for nodes to be ready
kind-cluster: $(KIND_KUBECONFIG) | $(NEEDS_KUBECTL)
	KUBECONFIG=~/.kube/config:$(KIND_KUBECONFIG) $(KUBECTL) config view --flatten > ~/.kube/config
	$(KUBECTL) config use-context kind-$(KIND_CLUSTER_NAME)

.PHONY: kind-cluster-clean
kind-cluster-clean: ## Delete the Kind cluster
kind-cluster-clean: $(NEEDS_KIND)
	$(KIND) delete cluster --name $(KIND_CLUSTER_NAME)
	rm -rf $(KIND_KUBECONFIG)

.PHONY: kind-logs
kind-logs: | kind-cluster $(NEEDS_KIND) $(ARTIFACTS)
	rm -rf $(ARTIFACTS)/e2e-logs
	mkdir -p $(ARTIFACTS)/e2e-logs
	$(KIND) export logs $(ARTIFACTS)/e2e-logs --name=$(KIND_CLUSTER_NAME)

$(ARTIFACTS):
	@mkdir -p $@

.PHONY: e2e-setup
e2e-setup: e2e-setup-cert-manager ## Setup e2e kind and install cert-manager dependency.

.PHONY: e2e-setup-cert-manager
e2e-setup-cert-manager: | kind-cluster images $(NEEDS_HELM) $(NEEDS_KUBECTL)
	$(HELM) upgrade \
		--install \
		--create-namespace \
		--wait \
		--namespace cert-manager \
		--repo https://charts.jetstack.io \
		--set installCRDs=true \
		--set featureGates="ServerSideApply=true\,LiteralCertificateSubject=true" \
		--set webhook.featureGates="ServerSideApply=true\,LiteralCertificateSubject=true" \
		--set image.repository=$(quay.io/jetstack/cert-manager-controller.REPO) \
		--set image.tag=$(quay.io/jetstack/cert-manager-controller.TAG) \
		--set image.pullPolicy=Never \
		--set cainjector.image.repository=$(quay.io/jetstack/cert-manager-cainjector.REPO) \
		--set cainjector.image.tag=$(quay.io/jetstack/cert-manager-cainjector.TAG) \
		--set cainjector.image.pullPolicy=Never \
		--set webhook.image.repository=$(quay.io/jetstack/cert-manager-webhook.REPO) \
		--set webhook.image.tag=$(quay.io/jetstack/cert-manager-webhook.TAG) \
		--set webhook.image.pullPolicy=Never \
		--set startupapicheck.image.repository=$(quay.io/jetstack/cert-manager-ctl.REPO) \
		--set startupapicheck.image.tag=$(quay.io/jetstack/cert-manager-ctl.TAG) \
		--set startupapicheck.image.pullPolicy=Never \
		cert-manager cert-manager >/dev/null
	$(KUBECTL) -n cert-manager apply -f ./make/config/cert-manager/approve.yaml
