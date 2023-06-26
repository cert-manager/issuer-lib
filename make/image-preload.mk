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

IMAGES_amd64 += docker.io/kindest/node:v1.27.2@sha256:ff631c3718962dc5a5e8adf1f48803c2675feebcd4eef674dd5a943576cf1d33
IMAGES_amd64 += quay.io/jetstack/cert-manager-controller:v1.12.1@sha256:2642e7f415456d27d7d98c955a47f493417dc5ed34f246a2ac3829f2a9f79ecd
IMAGES_amd64 += quay.io/jetstack/cert-manager-cainjector:v1.12.1@sha256:da7e239ee26491e47f7382ff731d4e53b003a2b75d776ceb9887d083ccae1831
IMAGES_amd64 += quay.io/jetstack/cert-manager-webhook:v1.12.1@sha256:a3205d0262460f72a5ceb78c8fa5f9571cb6f171281ba05f08d6c87625951760
IMAGES_amd64 += quay.io/jetstack/cert-manager-ctl:v1.12.1@sha256:174a8b7c246fcdfda1af64d9bf48acfbd1dfac99638059d819839ef9f05bde5e

IMAGES_arm64 += docker.io/kindest/node:v1.27.2@sha256:d48ca709adfa1b5d0109def39b5203ff5f8b4c1333082ca26772c24079f029d1
IMAGES_arm64 += quay.io/jetstack/cert-manager-controller:v1.12.1@sha256:d194c296ce771e023b65c12527c723ac5094483a9c2b0f6dfc0d605f331ee1cc
IMAGES_arm64 += quay.io/jetstack/cert-manager-cainjector:v1.12.1@sha256:917e390d61b92ea59e9620831d8ce43588a6ebd53d9131eb961c53c617022a59
IMAGES_arm64 += quay.io/jetstack/cert-manager-webhook:v1.12.1@sha256:f68de85e2ce6af244dd44818fc37b52a00d5f5807cd662518e702aa9c15d61ca
IMAGES_arm64 += quay.io/jetstack/cert-manager-ctl:v1.12.1@sha256:6557cab2e2dbb266259ec3cd00ebbcba03c440c7eee1b338b7d8177c4c74bd72

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
