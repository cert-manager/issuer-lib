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

repo_name := github.com/cert-manager/issuer-lib

kind_cluster_name := issuer-lib
kind_cluster_config := $(bin_dir)/scratch/kind_cluster.yaml

build_names := manager

go_manager_main_dir := .
go_manager_mod_dir := ./examples/simple
go_manager_ldflags := -X main.Version=$(VERSION)
oci_manager_base_image_flavor := static
oci_manager_image_name := cert-manager.local/simple-issuer
oci_manager_image_tag := $(VERSION)
oci_manager_image_name_development := cert-manager.local/simple-issuer

deploy_name := issuer-lib
deploy_namespace := cert-manager

api_docs_outfile := docs/api.md
api_docs_package := $(repo_name)/api/v1alpha1
api_docs_branch := main
