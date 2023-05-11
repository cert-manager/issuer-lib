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

IMAGES_amd64 += docker.io/kindest/node:v1.25.0@sha256:db0089929bbf03b5c6f2a4e2a7000e0b362900dbb5395d2c5f62a5a1daf8d54b
IMAGES_amd64 += quay.io/jetstack/cert-manager-controller:v1.9.1@sha256:81a5e25e2ecf63b96d6a0be28348d08a3055ea75793373109036977c24e34cf0
IMAGES_amd64 += quay.io/jetstack/cert-manager-cainjector:v1.9.1@sha256:4fdea639cac8a091ff9e85a403c3375c10848a23be64a2a4616e98acf81e40c3
IMAGES_amd64 += quay.io/jetstack/cert-manager-webhook:v1.9.1@sha256:b4e3d87f12f0197ebe0307803d6024f2b9e985bc02bbf450876e29ee6e6db4f1
IMAGES_amd64 += quay.io/jetstack/cert-manager-ctl:v1.9.1@sha256:917670524468c95b7e462ad9455b70c3ddadb4830057b77ba3474075c004272a

IMAGES_arm64 += docker.io/kindest/node:v1.25.0@sha256:330d2e41561eb88cad65b4816cb05becb7bcfc17f2331901272c639f1e45655b
IMAGES_arm64 += quay.io/jetstack/cert-manager-controller:v1.9.1@sha256:63feade2625bd65ce615f6459b5cddecd0d251c826746bf0ed1a63d0e869eec3
IMAGES_arm64 += quay.io/jetstack/cert-manager-cainjector:v1.9.1@sha256:a4438a013dbce6599b32389ac8634caf9b2f8214772773e86f820e8a11c0e226
IMAGES_arm64 += quay.io/jetstack/cert-manager-webhook:v1.9.1@sha256:d212c54682c77db8c8cccfc36a4747ce8f4ff6fc01ea3d2e2e4009e00f78421d
IMAGES_arm64 += quay.io/jetstack/cert-manager-ctl:v1.9.1@sha256:b83a73019c927046782ad1347bd9b0f3233f8c067b40fb07701bd25b7cdb7ac4

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
