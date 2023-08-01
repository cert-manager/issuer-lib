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

# To make sure we use the right version of each tool, we put symlink in
# $(BINDIR)/tools, and the actual binaries are in $(BINDIR)/downloaded. When bumping
# the version of the tools, this symlink gets updated.

# Let's have $(BINDIR)/tools in front of the PATH so that we don't inavertedly
# pick up the wrong binary somewhere. Watch out, $(shell echo $$PATH) will
# still print the original PATH, since GNU make does not honor exported
# variables: https://stackoverflow.com/questions/54726457
export PATH := $(PWD)/$(BINDIR)/tools:$(PATH)

CTR=docker

TOOLS :=
# https://github.com/helm/helm/releases
TOOLS += helm=v3.12.0
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
TOOLS += kubectl=v1.27.2
# https://github.com/kubernetes-sigs/kind/releases
TOOLS += kind=v0.19.0
# https://github.com/kyverno/kyverno/releases
TOOLS += kyverno=v1.10.0
# https://github.com/mikefarah/yq/releases
TOOLS += yq=v4.34.1
# https://github.com/ko-build/ko/releases
TOOLS += ko=0.13.0
TOOLS += ginkgo=$(shell awk '/ginkgo\/v2/ {print $$2}' ./conformance/go.mod)

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
TOOLS += controller-gen=v0.12.0
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
TOOLS += goimports=v0.9.1
# https://pkg.go.dev/github.com/google/go-licenses/licenses?tab=versions
TOOLS += go-licenses=v1.6.0
# https://pkg.go.dev/gotest.tools/gotestsum/testjson?tab=versions
TOOLS += gotestsum=v1.10.0
# https://pkg.go.dev/sigs.k8s.io/kustomize/kustomize/v4?tab=versions
TOOLS += kustomize=v4.5.7
# https://pkg.go.dev/github.com/itchyny/gojq?tab=versions
TOOLS += gojq=v0.12.12
# https://pkg.go.dev/github.com/google/go-containerregistry/pkg/crane?tab=versions
TOOLS += crane=v0.15.2
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
TOOLS += boilersuite=v0.1.0

# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
K8S_CODEGEN_VERSION=v0.27.2

# https://storage.googleapis.com/storage/v1/b/kubebuilder-tools/o/
KUBEBUILDER_ASSETS_VERSION=1.27.1
TOOLS += etcd=$(KUBEBUILDER_ASSETS_VERSION)
TOOLS += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# https://go.dev/dl/
VENDORED_GO_VERSION := 1.20.5

# When switching branches which use different versions of the tools, we
# need a way to re-trigger the symlinking from $(BINDIR)/downloaded to $(BINDIR)/tools.
$(BINDIR)/scratch/%_VERSION: FORCE | $(BINDIR)/scratch
	@test "$($*_VERSION)" == "$(shell cat $@ 2>/dev/null)" || echo $($*_VERSION) > $@

# The reason we don't use "go env GOOS" or "go env GOARCH" is that the "go"
# binary may not be available in the PATH yet when the Makefiles are
# evaluated. HOST_OS and HOST_ARCH only support Linux, *BSD and macOS (M1
# and Intel).
HOST_OS ?= $(shell uname -s | tr A-Z a-z)
HOST_ARCH ?= $(shell uname -m)
ifeq (x86_64, $(HOST_ARCH))
	HOST_ARCH = amd64
endif

# --silent = don't print output like progress meters
# --show-error = but do print errors when they happen
# --fail = exit with a nonzero error code without the response from the server when there's an HTTP error
# --location = follow redirects from the server
# --retry = the number of times to retry a failed attempt to connect
# --retry-connrefused = retry even if the initial connection was refused
CURL = curl --silent --show-error --fail --location --retry 10 --retry-connrefused

# In Prow, the pod has the folder "$(BINDIR)/downloaded" mounted into the
# container. For some reason, even though the permissions are correct,
# binaries that are mounted with hostPath can't be executed. When in CI, we
# copy the binaries to work around that. Using $(LN) is only required when
# dealing with binaries. Other files and folders can be symlinked.
#
# Details on how "$(BINDIR)/downloaded" gets cached are available in the
# description of the PR https://github.com/jetstack/testing/pull/651.
#
# We use "printenv CI" instead of just "ifeq ($(CI),)" because otherwise we
# would get "warning: undefined variable 'CI'".
ifeq ($(shell printenv CI),)
LN := ln -f -s
else
LN := cp -f -r
endif

UC = $(shell echo '$1' | tr a-z A-Z)
LC = $(shell echo '$1' | tr A-Z a-z)

TOOL_NAMES :=

# for each item `xxx` in the TOOLS variable:
# - a $(XXX_VERSION) variable is generated
#     -> this variable contains the version of the tool
# - a $(NEEDS_XXX) variable is generated
#     -> this variable contains the target name for the tool,
#        which is the relative path of the binary, this target
#        should be used when adding the tool as a dependency to
#        your target, you can't use $(XXX) as a dependency because
#        make does not support an absolute path as a dependency
# - a $(XXX) variable is generated
#     -> this variable contains the absolute path of the binary,
#        the absolute path should be used when executing the binary
#        in targets or in scripts, because it is agnostic to the
#        working directory
# - an unversioned target $(BINDIR)/tools/xxx is generated that
#   creates a copy/ link to the corresponding versioned target:
#   $(BINDIR)/tools/xxx@$(XXX_VERSION)_$(HOST_OS)_$(HOST_ARCH)
define tool_defs
TOOL_NAMES += $1

$(call UC,$1)_VERSION ?= $2
NEEDS_$(call UC,$1) := $$(BINDIR)/tools/$1
$(call UC,$1) := $$(PWD)/$$(BINDIR)/tools/$1

$$(BINDIR)/tools/$1: $$(BINDIR)/scratch/$(call UC,$1)_VERSION | $$(BINDIR)/downloaded/tools/$1@$$($(call UC,$1)_VERSION)_$$(HOST_OS)_$$(HOST_ARCH) $$(BINDIR)/tools
	cd $$(dir $$@) && $$(LN) $$(patsubst $$(BINDIR)/%,../%,$$(word 1,$$|)) $$(notdir $$@)
	@touch $$@ # making sure the target of the symlink is newer than *_VERSION
endef

$(foreach TOOL,$(TOOLS),$(eval $(call tool_defs,$(word 1,$(subst =, ,$(TOOL))),$(word 2,$(subst =, ,$(TOOL))))))

TOOLS_PATHS := $(TOOL_NAMES:%=$(BINDIR)/tools/%)

######
# Go #
######

# $(NEEDS_GO) is a target that is set as an order-only prerequisite in
# any target that calls $(GO), e.g.:
#
#     $(BINDIR)/tools/crane: $(NEEDS_GO)
#         $(GO) build -o $(BINDIR)/tools/crane
#
# $(NEEDS_GO) is empty most of the time, except when running "make vendor-go"
# or when "make vendor-go" was previously run, in which case $(NEEDS_GO) is set
# to $(BINDIR)/tools/go, since $(BINDIR)/tools/go is a prerequisite of
# any target depending on Go when "make vendor-go" was run.
NEEDS_GO := $(if $(findstring vendor-go,$(MAKECMDGOALS))$(shell [ -f $(BINDIR)/tools/go ] && echo yes), $(BINDIR)/tools/go,)
ifeq ($(NEEDS_GO),)
GO := go
else
export GOROOT := $(PWD)/$(BINDIR)/tools/goroot
export PATH := $(PWD)/$(BINDIR)/tools/goroot/bin:$(PATH)
GO := $(PWD)/$(BINDIR)/tools/go
endif

GOBUILD := CGO_ENABLED=$(CGO_ENABLED) GOMAXPROCS=$(GOBUILDPROCS) $(GO) build
GOTEST := CGO_ENABLED=$(CGO_ENABLED) $(GO) test

# overwrite $(GOTESTSUM) and add CGO_ENABLED variable
GOTESTSUM := CGO_ENABLED=$(CGO_ENABLED) $(GOTESTSUM)

.PHONY: vendor-go
## By default, this Makefile uses the system's Go. You can use a "vendored"
## version of Go that will get downloaded by running this command once. To
## disable vendoring, run "make unvendor-go". When vendoring is enabled,
## you will want to set the following:
##
##     export PATH="$PWD/$(BINDIR)/tools:$PATH"
##     export GOROOT="$PWD/$(BINDIR)/tools/goroot"
vendor-go: $(BINDIR)/tools/go

.PHONY: unvendor-go
unvendor-go: $(BINDIR)/tools/go
	rm -rf $(BINDIR)/tools/go $(BINDIR)/tools/goroot

.PHONY: which-go
## Print the version and path of go which will be used for building and
## testing in Makefile commands. Vendored go will have a path in ./bin
which-go: | $(NEEDS_GO)
	@$(GO) version
	@echo "go binary used for above version information: $(GO)"

# The "_" in "_go "prevents "go mod tidy" from trying to tidy the vendored
# goroot.
$(BINDIR)/tools/go: $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$(HOST_OS)-$(HOST_ARCH)/goroot/bin/go $(BINDIR)/tools/goroot $(BINDIR)/scratch/VENDORED_GO_VERSION | $(BINDIR)/tools
	cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) .
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

$(BINDIR)/tools/goroot: $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$(HOST_OS)-$(HOST_ARCH)/goroot $(BINDIR)/scratch/VENDORED_GO_VERSION | $(BINDIR)/tools
	@rm -rf $(BINDIR)/tools/goroot
	cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) .
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

$(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-%/goroot $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-%/goroot/bin/go: $(BINDIR)/downloaded/tools/go-$(VENDORED_GO_VERSION)-%.tar.gz
	@mkdir -p $(dir $@)
	rm -rf $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/goroot
	tar xzf $< -C $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*
	mv $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/go $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/goroot

$(BINDIR)/downloaded/tools/go-$(VENDORED_GO_VERSION)-%.tar.gz: | $(BINDIR)/downloaded/tools
	$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$*.tar.gz -o $@

###################
# go dependencies #
###################

GO_DEPENDENCIES :=
GO_DEPENDENCIES += ginkgo=github.com/onsi/ginkgo/v2/ginkgo
GO_DEPENDENCIES += controller-gen=sigs.k8s.io/controller-tools/cmd/controller-gen
GO_DEPENDENCIES += goimports=golang.org/x/tools/cmd/goimports
GO_DEPENDENCIES += go-licenses=github.com/google/go-licenses
GO_DEPENDENCIES += gotestsum=gotest.tools/gotestsum
GO_DEPENDENCIES += kustomize=sigs.k8s.io/kustomize/kustomize/v4
GO_DEPENDENCIES += gojq=github.com/itchyny/gojq/cmd/gojq
GO_DEPENDENCIES += crane=github.com/google/go-containerregistry/cmd/crane
GO_DEPENDENCIES += boilersuite=github.com/cert-manager/boilersuite

define go_dependency
$$(BINDIR)/downloaded/tools/$1@$($(call UC,$1)_VERSION)_%: | $$(NEEDS_GO) $$(BINDIR)/downloaded/tools
	GOBIN=$$(PWD)/$$(dir $$@) $$(GO) install $2@$($(call UC,$1)_VERSION)
	@mv $$(PWD)/$$(dir $$@)/$1 $$@
endef

$(foreach GO_DEPENDENCY,$(GO_DEPENDENCIES),$(eval $(call go_dependency,$(word 1,$(subst =, ,$(GO_DEPENDENCY))),$(word 2,$(subst =, ,$(GO_DEPENDENCY))))))

########
# Helm #
########

HELM_linux_amd64_SHA256SUM=da36e117d6dbc57c8ec5bab2283222fbd108db86c83389eebe045ad1ef3e2c3b
HELM_darwin_amd64_SHA256SUM=8223beb796ff19b59e615387d29be8c2025c5d3aea08485a262583de7ba7d708
HELM_darwin_arm64_SHA256SUM=879f61d2ad245cb3f5018ab8b66a87619f195904a4df3b077c98ec0780e36c37

$(BINDIR)/downloaded/tools/helm@$(HELM_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(subst _,-,$*).tar.gz -o $@.tar.gz
	./make/util/checkhash.sh $@.tar.gz $(HELM_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $@.tar.gz $(subst _,-,$*)/helm > $@
	chmod +x $@
	rm -f $@.tar.gz

###########
# kubectl #
###########

KUBECTL_linux_amd64_SHA256SUM=4f38ee903f35b300d3b005a9c6bfb9a46a57f92e89ae602ef9c129b91dc6c5a5
KUBECTL_darwin_amd64_SHA256SUM=ec954c580e4f50b5a8aa9e29132374ce54390578d6e95f7ad0b5d528cb025f85
KUBECTL_darwin_arm64_SHA256SUM=d2b045b1a0804d4c46f646aeb6dcd278202b9da12c773d5e462b1b857d1f37d7

$(BINDIR)/downloaded/tools/kubectl@$(KUBECTL_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(subst _,/,$*)/kubectl -o $@
	./make/util/checkhash.sh $@ $(KUBECTL_$*_SHA256SUM)
	chmod +x $@

########
# kind #
########

KIND_linux_amd64_SHA256SUM=b543dca8440de4273be19ad818dcdfcf12ad1f767c962242fcccdb383dff893b
KIND_darwin_amd64_SHA256SUM=32bd46859a98bffdfc2e594850c4147d297b3f93007f8376b6d4a28e82dee29a
KIND_darwin_arm64_SHA256SUM=2628c53ddf4a2de19950df0452176e400e33b8c83834afab93651c2b6f9546bd

$(BINDIR)/downloaded/tools/kind@$(KIND_VERSION)_%: | $(BINDIR)/downloaded/tools $(BINDIR)/tools
	$(CURL) -sSfL https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)/kind-$(subst _,-,$*) -o $@
	./make/util/checkhash.sh $@ $(KIND_$*_SHA256SUM)
	chmod +x $@

#####################
# k8s codegen tools #
#####################

K8S_CODEGEN_TOOLS := applyconfiguration-gen
K8S_CODEGEN_TOOLS_PATHS := $(K8S_CODEGEN_TOOLS:%=$(BINDIR)/tools/%)
K8S_CODEGEN_TOOLS_DOWNLOADS := $(K8S_CODEGEN_TOOLS:%=$(BINDIR)/downloaded/tools/%@$(K8S_CODEGEN_VERSION))

k8s-codegen-tools: $(K8S_CODEGEN_TOOLS_PATHS)

$(K8S_CODEGEN_TOOLS_PATHS): $(BINDIR)/tools/%-gen: $(BINDIR)/scratch/K8S_CODEGEN_VERSION | $(BINDIR)/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION) $(BINDIR)/tools
	cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$(word 1,$|)) $(notdir $@)
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

$(K8S_CODEGEN_TOOLS_DOWNLOADS): $(BINDIR)/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION): $(NEEDS_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install k8s.io/code-generator/cmd/$(notdir $@)
	@mv $(subst @$(K8S_CODEGEN_VERSION),,$@) $@

############################
# kubebuilder-tools assets #
# kube-apiserver / etcd    #
############################

KUBEBUILDER_TOOLS_linux_amd64_SHA256SUM=a12ae2dd2a4968530ae4887cd943b86a5ff131723d991303806fcd45defc5220
KUBEBUILDER_TOOLS_darwin_amd64_SHA256SUM=e1913674bacaa70c067e15649237e1f67d891ba53f367c0a50786b4a274ee047
KUBEBUILDER_TOOLS_darwin_arm64_SHA256SUM=0422632a2bbb0d4d14d7d8b0f05497a4d041c11d770a07b7a55c44bcc5e8ce66

$(BINDIR)/downloaded/tools/etcd@$(KUBEBUILDER_ASSETS_VERSION)_%: $(BINDIR)/downloaded/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_%.tar.gz | $(BINDIR)/downloaded/tools
	./make/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/etcd > $@ && chmod 775 $@

$(BINDIR)/downloaded/tools/kube-apiserver@$(KUBEBUILDER_ASSETS_VERSION)_%: $(BINDIR)/downloaded/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_%.tar.gz | $(BINDIR)/downloaded/tools
	./make/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/kube-apiserver > $@ && chmod 775 $@

$(BINDIR)/downloaded/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(BINDIR)/downloaded/tools
	$(CURL) https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $@

###########
# kyverno #
###########

KYVERNO_linux_amd64_SHA256SUM=ee0a08fa4a9f43a6e16e60496cf7b31a11460ce3f107599c45b9f616e48ed93f
KYVERNO_darwin_amd64_SHA256SUM=35154ba9f508f74c9facf4b59898a99d5596056c541a44df8187da4bb34cfa4c
KYVERNO_darwin_arm64_SHA256SUM=ad3261f225e888d8174b65a96bfd4527e1202c2167de54d1435b2d16058fcf83

$(BINDIR)/downloaded/tools/kyverno@$(KYVERNO_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(subst amd64,x86_64,$*).tar.gz	-fsSL -o $@.tar.gz
	./make/util/checkhash.sh $@.tar.gz $(KYVERNO_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $@.tar.gz kyverno > $@
	chmod +x $@
	rm -f $@.tar.gz

######
# yq #
######

YQ_linux_amd64_SHA256SUM=c5a92a572b3bd0024c7b1fe8072be3251156874c05f017c23f9db7b3254ae71a
YQ_darwin_amd64_SHA256SUM=25ccdecfd02aa37e07c985ac9612f17e5fd2c9eb40b051d43936bf3b99c9c2f5
YQ_darwin_arm64_SHA256SUM=30e8c7c52647f26312d8709193a269ec0ba4f384712775f87241b2abdc46de85

$(BINDIR)/downloaded/tools/yq@$(YQ_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$* -o $@
	./make/util/checkhash.sh $@ $(YQ_$*_SHA256SUM)
	chmod +x $@

######
# ko #
######

KO_linux_amd64_SHA256SUM=80f3e3148fabd5b839cc367ac56bb4794f90e7262b01911316c670b210b574cc
KO_darwin_amd64_SHA256SUM=8d9daea9bcf25c790f705ea115d1c0a0193cb3d9759e937ab2959c71f88ce29c
KO_darwin_arm64_SHA256SUM=8b6ad2ca95de9e9a5f697f6a653301ef5405a643b09bdd10628bac0f77eaadff

$(BINDIR)/downloaded/tools/ko@$(KO_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/ko-build/ko/releases/download/v$(KO_VERSION)/ko_$(KO_VERSION)_$(subst linux,Linux,$(subst darwin,Darwin,$(subst amd64,x86_64,$*))).tar.gz -o $@.tar.gz
	./make/util/checkhash.sh $@.tar.gz $(KO_$*_SHA256SUM)
	tar xfO $@.tar.gz ko > $@
	chmod +x $@
	rm -f $@.tar.gz

#################
# Other Targets #
#################

$(BINDIR) $(BINDIR)/scratch $(BINDIR)/tools $(BINDIR)/downloaded $(BINDIR)/downloaded/tools:
	@mkdir -p $@

# Although we "vendor" most tools in $(BINDIR)/tools, we still require some binaries
# to be available on the system. The vendor-go MAKECMDGOALS trick prevents the
# check for the presence of Go when 'make vendor-go' is run.

# Gotcha warning: MAKECMDGOALS only contains what the _top level_ make invocation used, and doesn't look at target dependencies
# i.e. if we have a target "abc: vendor-go test" and run "make abc", we'll get an error
# about go being missing even though abc itself depends on vendor-go!
# That means we need to pass vendor-go at the top level if go is not installed (i.e. "make vendor-go abc")

MISSING=$(shell (command -v curl >/dev/null || echo curl) \
             && (command -v sha256sum >/dev/null || echo sha256sum) \
             && (command -v git >/dev/null || echo git) \
             && ([ -n "$(findstring vendor-go,$(MAKECMDGOALS),)" ] \
                || command -v $(GO) >/dev/null || echo "$(GO) (or run 'make vendor-go')") \
             && (command -v $(CTR) >/dev/null || echo "$(CTR) (or set CTR to a docker-compatible tool)"))
ifneq ($(MISSING),)
$(error Missing required tools: $(MISSING))
endif

# re-download all tools and replace the sha values if changed
# useful for determining the sha values after upgrading
learn-sha-tools:
	rm -rf ./_bin/
	mkdir ./_bin/
	$(eval export LEARN_FILE=$(PWD)/_bin/learn_file)
	echo -n "" > "$(LEARN_FILE)"

	HOST_OS=linux HOST_ARCH=amd64 $(MAKE) tools
	HOST_OS=darwin HOST_ARCH=amd64 $(MAKE) tools
	HOST_OS=darwin HOST_ARCH=arm64 $(MAKE) tools

	while read p; do \
		sed -i "$$p" ./make/tools.mk; \
	done <"$(LEARN_FILE)"
