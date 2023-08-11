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

CRI_ARCH := $(HOST_ARCH)

IMAGES_amd64 += docker.io/kindest/node:v1.27.3@sha256:9dd3392d79af1b084671b05bcf65b21de476256ad1dcc853d9f3b10b4ac52dde
IMAGES_amd64 += quay.io/jetstack/cert-manager-controller:v1.12.3@sha256:6b9b696c2e56aaef5bf7e0b659ee91a773d0bb8f72b0eb4914a9db7e87578d47
IMAGES_amd64 += quay.io/jetstack/cert-manager-cainjector:v1.12.3@sha256:31ffa7640020640345a34f3fe6964560665e7ca89d818a6c455e63f5c4f5eb14
IMAGES_amd64 += quay.io/jetstack/cert-manager-webhook:v1.12.3@sha256:292facf28fd4f0db074fed12437669eef9c0ab8c1b9812d2c91e42b4a7448a36
IMAGES_amd64 += quay.io/jetstack/cert-manager-ctl:v1.12.3@sha256:5c985c4ebd8da6592cbe0249936f7513c0527488d754198699b3be9389b8b587

IMAGES_arm64 += docker.io/kindest/node:v1.27.3@sha256:de0b3dfe848ccf07e24f4278eaf93edb857b6231b39773f46b36a2b1a6543ae9
IMAGES_arm64 += quay.io/jetstack/cert-manager-controller:v1.12.3@sha256:3a218da3db0b05bf487729b07374662b73805a44e6568a2661bba659b22110b2
IMAGES_arm64 += quay.io/jetstack/cert-manager-cainjector:v1.12.3@sha256:118b985b0f0051ee9c428a3736c47bea92c3d8e7cb7c6eda881f7ecd4430cbed
IMAGES_arm64 += quay.io/jetstack/cert-manager-webhook:v1.12.3@sha256:0195441dc0f7f81e7514e6497bf68171bc54ef8481efc5fa0efe51892bd28c36
IMAGES_arm64 += quay.io/jetstack/cert-manager-ctl:v1.12.3@sha256:f376994ae17c519b12dd59c406a0abf8c6265c5f0c57431510eee15eaa40e4eb

IMAGES := $(IMAGES_$(CRI_ARCH))
IMAGES_FILES := $(foreach IMAGE,$(IMAGES),$(subst :,+,$(IMAGE)))

IMAGES_TAR_DIR := $(BINDIR)/downloaded/containers/$(CRI_ARCH)
IMAGES_TARS := $(IMAGES_FILES:%=$(IMAGES_TAR_DIR)/%.tar)

$(IMAGES_TARS): $(IMAGES_TAR_DIR)/%.tar: | $(NEEDS_CRANE)
	@$(eval IMAGE=$(subst +,:,$*))
	@$(eval IMAGE_WITHOUT_DIGEST=$(shell cut -d@ -f1 <<<"$(IMAGE)"))
	@$(eval DIGEST=$(subst $(IMAGE_WITHOUT_DIGEST)@,,$(IMAGE)))
	@mkdir -p $(dir $@)
	diff <(echo "$(DIGEST)  -" | cut -d: -f2) <($(CRANE) manifest $(IMAGE) | sha256sum)
	$(CRANE) pull $(IMAGE_WITHOUT_DIGEST) $@ --platform=linux/$(CRI_ARCH)

IMAGES_TAR_ENVS := $(IMAGES_FILES:%=env-%)

.PHONY: $(IMAGES_TAR_ENVS)
$(IMAGES_TAR_ENVS): env-%: $(IMAGES_TAR_DIR)/%.tar | $(NEEDS_GOJQ)
	@$(eval IMAGE_WITHOUT_TAG=$(shell cut -d+ -f1 <<<"$*"))
	@$(eval $(IMAGE_WITHOUT_TAG).TAR="$(IMAGES_TAR_DIR)/$*.tar")
	@$(eval $(IMAGE_WITHOUT_TAG).REPO=$(shell tar xfO "$(IMAGES_TAR_DIR)/$*.tar" manifest.json | $(GOJQ) '.[0].RepoTags[0]' -r | cut -d: -f1))
	@$(eval $(IMAGE_WITHOUT_TAG).TAG=$(shell tar xfO "$(IMAGES_TAR_DIR)/$*.tar" manifest.json | $(GOJQ) '.[0].RepoTags[0]' -r | cut -d: -f2))
	@$(eval $(IMAGE_WITHOUT_TAG).FULL=$($(IMAGE_WITHOUT_TAG).REPO):$($(IMAGE_WITHOUT_TAG).TAG))

.PHONY: images
images: | $(IMAGES_TAR_ENVS)
