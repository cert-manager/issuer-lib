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

MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.SUFFIXES:
FORCE:

VERSION ?= $(shell git describe --tags --always --dirty --match='v*' --abbrev=14)

BINDIR := _bin

.PHONY: all
all: help

## By default, we don't link Go binaries to the libc. In some case, you might
## want to build libc-linked binaries, in which case you can set this to "1".
## @category Build
CGO_ENABLED ?= 0

## GOBUILDPROCS is passed to GOMAXPROCS when running go build; if you're running
## make in parallel using "-jN" then you'll probably want to reduce the value
## of GOBUILDPROCS or else you could end up running N parallel invocations of
## go build, each of which will spin up as many threads as are available on your
## system.
## @category Build
GOBUILDPROCS ?=

ARTIFACTS ?= $(shell pwd)/$(BINDIR)/artifacts

# Default is `cert-manager.local` (a non-existent registry) so that developers don't
# accidentally push images to the production registry.
# If set to kind.local, ko will upload the Docker image to the current Kind cluster,
# obviating the use of `kind load`.
# If set to ko.local, ko will publish the Docker image to the local Docker
# server. This is not the default because not all systems will have a Docker
# daemon running.
DOCKER_REGISTRY ?= cert-manager.local
DOCKER_REPO_NAME ?= issuer-lib
DOCKER_TAG ?= $(VERSION)
# Empty by default which causes ko to only build images for the host platform.
# Set to `all` in the release workflow which causes ko to build multi-arch
# Docker image for all platforms.
DOCKER_IMAGE_PLATFORMS ?=
# A file where ko will save a tar archive of the Docker image.
# This is only generated when DOCKER_IMAGE_PLATFORMS is empty (the default)
# because ko can not create a tarball for multi-arch images.
DOCKER_IMAGE_TAR ?= $(BINDIR)/scratch/docker-image.$(VERSION).tar

# This tells ko to store a local mapping between the go build inputs to the
# image layer that they produce, so go build can be skipped entirely if the go
# files are unchanged. https://ko.build/features/build-cache/
KOCACHE ?= $(BINDIR)/scratch/ko/cache

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build Dependencies

include make/tools.mk
include make/image-preload.mk

.PHONY: tools
tools: ## Download and setup all tools
tools: $(TOOLS_PATHS) $(K8S_CODEGEN_TOOLS_PATHS)

##@ Development

.PHONY: generate-manifests
generate-manifests: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
generate-manifests: | $(NEEDS_CONTROLLER-GEN)
	$(CONTROLLER-GEN) rbac:roleName=simple-issuer-controller-role crd \
		paths="./examples/simple/..." \
		output:crd:artifacts:config=examples/simple/deploy/crds \
		output:rbac:artifacts:config=examples/simple/deploy/rbac

.PHONY: generate-deepcopy
generate-deepcopy: ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
generate-deepcopy: | $(NEEDS_CONTROLLER-GEN)
	$(CONTROLLER-GEN) object:headerFile="make/boilerplate/boilerplate.go.txt" paths="./..."

.PHONY: generate
generate: ## Generate all generate targets.
generate: generate-manifests generate-deepcopy

.PHONY: fmt
fmt: | $(NEEDS_GO) ## Run go fmt against code.
	$(GO) fmt ./...

.PHONY: vet
vet: | $(NEEDS_GO) ## Run go vet against code.
	$(GO) vet ./...

# Run the supplied make target argument in a temporary workspace and diff the results.
verify-%: FORCE
	./make/util/verify.sh $(MAKE) -s $*

.PHONY: verify-boilerplate
verify-boilerplate: ## Verify that all files have the correct boilerplate.
verify-boilerplate: | $(NEEDS_BOILERSUITE)
	$(BOILERSUITE) .

.PHONY: verify
verify: ## Run all verify targets.
verify: verify-generate-manifests
verify: verify-generate-deepcopy
verify: verify-boilerplate

##@ Testing

include make/e2e-setup.mk

include make/test.mk

test-unit-deps: TEST_MODE := UNIT
test-unit-deps: test-envs

# Although the targets "docker-build" and "install" can be run
# on their own with any currently active cluster, we can't use any other cluster
# when a target containing "test-e2e" is run. When a "test-e2e" target is run,
# the currently active cluster must be the kind cluster created by the
# "kind-cluster" target.
ifeq ($(findstring test-e2e,$(MAKECMDGOALS)),test-e2e)
install: kind-cluster docker-build
docker-build: kind-cluster
endif

test-e2e-deps: TEST_MODE := E2E
test-e2e-deps: DOCKER_REGISTRY := kind.local
test-e2e-deps: e2e-setup docker-build test-e2e-envs install

.PHONY: test
test: test-unit-deps | $(NEEDS_GO) $(NEEDS_GOTESTSUM) ## Run unit tests.
	$(GOTESTSUM) ./... -coverprofile cover.out

.PHONY: test-e2e
test-e2e: test-e2e-deps | $(NEEDS_GOTESTSUM) ## Run e2e tests. This creates a Kind cluster, installs dependencies, deploys the issuer-lib and runs the E2E tests.
	cd ./examples/simple/e2e && \
	KUBECONFIG=$(PWD)/$(KIND_KUBECONFIG) \
	$(GOTESTSUM) ./... -coverprofile cover.out -timeout 1m

##@ Build

.PHONY: build
build: generate | $(NEEDS_GO) ## Build manager binary.
	$(GOBUILD) -o bin/manager main.go

.PHONY: run
ARGS ?= # default empty
run: generate | $(NEEDS_GO) ## Run a controller from your host.
	$(GO) run ./main.go $(ARGS)

# Defaults to false to prevent ko from pushing the Docker image to DOCKER_REGISTRY.
# Overridden to true by docker-push.
ko_push = false

# docker-build can both build the Docker image and push it to a DOCKER_REGISTRY
# depending on the value of ko_push.
# It can also create a local tar archive of the Docker image, but not when
# building multi-arch images.
# ko will automatically upload the Docker image to a Kind cluster when
# DOCKER_REGISTRY=kind.local, as set in test-e2e.
.PHONY: docker-build
docker-build: ## Build the docker image.
docker-build: | $(NEEDS_KO)
	KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) \
	KO_DOCKER_REPO=$(DOCKER_REGISTRY) \
	KOCACHE=$(CURDIR)/$(KOCACHE) \
	$(KO) build ./examples/simple \
		--platform=$(DOCKER_IMAGE_PLATFORMS) \
		$(if $(DOCKER_IMAGE_PLATFORMS),,--tarball=$(DOCKER_IMAGE_TAR)) \
		--tags=$(DOCKER_TAG) \
		--push=$(ko_push) \
		--base-import-paths

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
docker-push: ko_push = true
docker-push: docker-build

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

$(BINDIR)/scratch/yaml/kustomization.yaml: FORCE | $(NEEDS_KUSTOMIZE)
	rm -rf $(BINDIR)/scratch/yaml
	mkdir -p $(BINDIR)/scratch/yaml

	cd $(BINDIR)/scratch/yaml; \
	$(KUSTOMIZE) create \
		--namespace "my-namespace" \
		--nameprefix "simple-issuer-" \
		--resources ../../../examples/simple/deploy/static/

	cd $(BINDIR)/scratch/yaml; \
	$(KUSTOMIZE) edit set image "controller:latest=$(DOCKER_REGISTRY)/simple-issuer:$(DOCKER_TAG)"

.PHONY: install
install: generate-manifests $(BINDIR)/scratch/yaml/kustomization.yaml | $(NEEDS_KUBECTL) $(NEEDS_YQ) ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUBECTL) apply -f examples/simple/deploy/crds
	$(KUBECTL) apply -f examples/simple/deploy/rbac
	$(KUBECTL) apply -k $(BINDIR)/scratch/yaml/

.PHONY: uninstall
uninstall: generate-manifests | $(NEEDS_KUBECTL) ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f examples/simple/deploy/crds

TEMP_DIR := _tmp
.PHONY: clean
clean:
	@mkdir -p $(BINDIR)/downloaded
	@mkdir -p $(TEMP_DIR)/downloaded
	@mv $(BINDIR)/downloaded $(TEMP_DIR)
	@rm -rf $(BINDIR)
	@mkdir -p $(BINDIR)/downloaded
	@mv $(TEMP_DIR)/downloaded $(BINDIR)
	@rmdir $(TEMP_DIR)
