/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rbac

import (
	"conformance/framework"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func (s *Suite) defineIssuers() {
	RBACDescribe("Issuers", func() {
		f := framework.NewFramework("rbac-issuers", s.KubeClientConfig)
		resource := "issuers" // this file is related to issuers

		Context("with namespace view access", func() {
			clusterRole := "view"
			It("shouldn't be able to create issuers", func() {
				verb := "create"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeFalse())
			})

			It("shouldn't be able to delete issuers", func() {
				verb := "delete"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeFalse())
			})

			It("shouldn't be able to delete collections of issuers", func() {
				verb := "deletecollection"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeFalse())
			})

			It("shouldn't be able to patch issuers", func() {
				verb := "patch"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeFalse())
			})

			It("shouldn't be able to update issuers", func() {
				verb := "update"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeFalse())
			})

			It("should be able to get issuers", func() {
				verb := "get"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to list issuers", func() {
				verb := "list"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to watch issuers", func() {
				verb := "watch"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})
		})
		Context("with namespace edit access", func() {
			clusterRole := "edit"
			It("should be able to create issuers", func() {
				verb := "create"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to delete issuers", func() {
				verb := "delete"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to delete collections of issuers", func() {
				verb := "deletecollection"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to patch issuers", func() {
				verb := "patch"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to update issuers", func() {
				verb := "update"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to get issuers", func() {
				verb := "get"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to list issuers", func() {
				verb := "list"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to watch issuers", func() {
				verb := "watch"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})
		})

		Context("with namespace admin access", func() {
			clusterRole := "admin"
			It("should be able to create issuers", func() {
				verb := "create"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to delete issuers", func() {
				verb := "delete"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to delete collections of issuers", func() {
				verb := "deletecollection"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to patch issuers", func() {
				verb := "patch"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to update issuers", func() {
				verb := "update"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to get issuers", func() {
				verb := "get"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to list issuers", func() {
				verb := "list"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})

			It("should be able to watch issuers", func() {
				verb := "watch"

				hasAccess := RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
				Expect(hasAccess).Should(BeTrue())
			})
		})
	})
}
