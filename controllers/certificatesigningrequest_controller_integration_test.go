/*
Copyright 2026 The cert-manager Authors.

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

package controllers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/testapi/api"
	"github.com/cert-manager/issuer-lib/internal/testapi/testutil"
	"github.com/cert-manager/issuer-lib/internal/tests/testresource"
)

// TestCertificateSigningRequestNamespacedIssuerAuthorization runs the
// CombinedController, with EnableNamespacedIssuerCSR set, against a real
// Kubernetes API server with RBAC authorization enabled.
//
// It checks that a Kubernetes CSR referencing a namespaced Issuer is only
// signed when the CSR requester holds the "reference" verb on "signers" in the
// Issuer's namespace, mirroring the behaviour of the in-tree cert-manager CSR
// controllers.
func TestCertificateSigningRequestNamespacedIssuerAuthorization(t *testing.T) { //nolint:tparallel
	t.Parallel()

	t.Log(
		"Tests to show that the CertificateSigningRequest controller authorizes the CSR requester",
		"through a SubjectAccessReview before signing a CSR that references a namespaced Issuer:",
		"a requester without the \"reference\" permission gets a terminal Failed/DeniedReference condition,",
		"a requester with the permission (by name or for all signers in the namespace) gets a certificate",
	)

	const (
		fieldOwner = "certificatesigningrequest-namespaced-issuer-authorization"
		requester  = "alice"
	)

	ctx := t.Context()
	kubeClients := testresource.KubeClients(t, nil)

	signedCert := selfSignedCertificatePEM(t)

	ctx = setupControllersAPIServerAndClient(t, ctx, kubeClients,
		func(mgr ctrl.Manager) controllerInterface {
			return &CombinedController{
				IssuerTypes:        []v1alpha1.Issuer{&api.TestIssuer{}},
				ClusterIssuerTypes: []v1alpha1.Issuer{&api.TestClusterIssuer{}},
				FieldOwner:         fieldOwner,
				MaxRetryDuration:   time.Minute,

				EnableNamespacedIssuerCSR: true,

				Check: func(_ context.Context, _ v1alpha1.Issuer) error {
					return nil
				},
				Sign: func(_ context.Context, _ signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
					return signer.PEMBundle{
						ChainPEM: signedCert,
					}, nil
				},
				EventRecorder: events.NewFakeRecorder(100),
			}
		},
	)

	// The requester needs to be able to create CSRs at all. Impersonation makes
	// the API server record "alice" as the CSR's spec.username, which is what
	// the controller feeds into the SubjectAccessReview.
	grantClusterWideCSRCreate(t, ctx, kubeClients.KubeClient, requester)
	requesterClient := impersonatingClientset(t, kubeClients.Rest, requester)

	type testcase struct {
		name string

		// referenceRule, when non-nil, is bound to the requester in the Issuer's
		// namespace before the CSR is created.
		referenceRule *rbacv1.PolicyRule

		expectCertificate bool
		expectedCondition *certificatesv1.CertificateSigningRequestCondition
	}

	testcases := []testcase{
		{
			name:              "denied-without-reference-permission",
			referenceRule:     nil,
			expectCertificate: false,
			expectedCondition: &certificatesv1.CertificateSigningRequestCondition{
				Type:   certificatesv1.CertificateFailed,
				Status: corev1.ConditionTrue,
				Reason: "DeniedReference",
			},
		},
		{
			name: "allowed-with-reference-permission-by-name",
			referenceRule: &rbacv1.PolicyRule{
				APIGroups:     []string{api.SchemeGroupVersion.Group},
				Resources:     []string{"signers"},
				Verbs:         []string{"reference"},
				ResourceNames: []string{"issuer-1"},
			},
			expectCertificate: true,
		},
		{
			name: "allowed-with-reference-permission-for-all-signers",
			referenceRule: &rbacv1.PolicyRule{
				APIGroups: []string{api.SchemeGroupVersion.Group},
				Resources: []string{"signers"},
				Verbs:     []string{"reference"},
			},
			expectCertificate: true,
		},
		{
			name: "denied-with-reference-permission-for-other-issuer-name",
			referenceRule: &rbacv1.PolicyRule{
				APIGroups:     []string{api.SchemeGroupVersion.Group},
				Resources:     []string{"signers"},
				Verbs:         []string{"reference"},
				ResourceNames: []string{"some-other-issuer"},
			},
			expectCertificate: false,
			expectedCondition: &certificatesv1.CertificateSigningRequestCondition{
				Type:   certificatesv1.CertificateFailed,
				Status: corev1.ConditionTrue,
				Reason: "DeniedReference",
			},
		},
	}

	// run tests sequentially: they share one API server and one controller
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("Creating a namespace")
			namespace, cleanup := kubeClients.SetupNamespace(t, ctx)
			defer cleanup()

			issuer := testutil.TestIssuer(
				"issuer-1",
				testutil.SetTestIssuerNamespace(namespace),
			)

			if tc.referenceRule != nil {
				t.Log("Granting the requester the \"reference\" permission in the Issuer namespace")
				grantInNamespace(t, ctx, kubeClients.KubeClient, namespace, requester, *tc.referenceRule)
			}

			t.Log("Creating the TestIssuer and waiting for it to be Ready")
			checkIssuerReady := kubeClients.StartObjectWatch(t, ctx, issuer)
			require.NoError(t, kubeClients.Client.Create(ctx, issuer))
			require.NoError(t, checkIssuerReady(func(obj runtime.Object) error {
				for _, cond := range obj.(*api.TestIssuer).Status.Conditions {
					if cond.Type == v1alpha1.IssuerConditionTypeReady && cond.Status == metav1.ConditionTrue {
						return nil
					}
				}
				return fmt.Errorf("issuer not ready yet")
			}, watch.Added, watch.Modified))

			csr := newCSRForNamespacedIssuer(t, namespace, issuer)

			t.Logf("Creating the CSR as %q", requester)
			created, err := requesterClient.CertificatesV1().CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})
			require.NoError(t, err)
			require.Equal(t, requester, created.Spec.Username, "API server must record the impersonated requester")
			t.Cleanup(func() {
				_ = kubeClients.KubeClient.CertificatesV1().CertificateSigningRequests().Delete(context.WithoutCancel(ctx), created.Name, metav1.DeleteOptions{})
			})

			checkCSRComplete := kubeClients.StartObjectWatch(t, ctx, created)

			t.Log("Approving the CSR")
			approveCSR(t, ctx, kubeClients.KubeClient, created)

			t.Log("Waiting for the controller to sign or fail the CSR")
			require.NoError(t, checkCSRComplete(func(obj runtime.Object) error {
				got := obj.(*certificatesv1.CertificateSigningRequest)

				if tc.expectCertificate {
					if len(got.Status.Certificate) == 0 {
						return fmt.Errorf("certificate not yet issued, conditions: %v", got.Status.Conditions)
					}
					require.Equal(t, signedCert, got.Status.Certificate)
					for _, cond := range got.Status.Conditions {
						require.NotEqual(t, certificatesv1.CertificateFailed, cond.Type, "a signed CSR must not also be Failed: %v", cond)
					}
					return nil
				}

				require.Empty(t, got.Status.Certificate, "a denied CSR must never be signed")
				for _, cond := range got.Status.Conditions {
					if cond.Type != tc.expectedCondition.Type {
						continue
					}
					if cond.Status != tc.expectedCondition.Status || cond.Reason != tc.expectedCondition.Reason {
						return fmt.Errorf("unexpected %s condition: %v", cond.Type, cond)
					}
					require.Equal(t,
						fmt.Sprintf("Requester may not reference Namespaced Issuer %s/%s", namespace, issuer.Name),
						cond.Message,
					)
					return nil
				}
				return fmt.Errorf("condition %s not yet present, conditions: %v", tc.expectedCondition.Type, got.Status.Conditions)
			}, watch.Added, watch.Modified))
		})
	}
}

// newCSRForNamespacedIssuer builds a CSR whose signerName references the given
// namespaced Issuer using the "<issuer-type-id>/<namespace>.<name>" format.
func newCSRForNamespacedIssuer(t *testing.T, namespace string, issuer *api.TestIssuer) *certificatesv1.CertificateSigningRequest {
	t.Helper()

	csrPEM, _, err := cmgen.CSR(x509.ECDSA, func(c *x509.CertificateRequest) error {
		c.Subject.CommonName = "namespaced-issuer-csr"
		return nil
	})
	require.NoError(t, err)

	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			// CSRs are cluster-scoped; namespace in the name keeps parallel
			// subtests from colliding.
			Name: fmt.Sprintf("csr-%s", namespace),
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csrPEM,
			SignerName: fmt.Sprintf("%s/%s.%s", issuer.GetIssuerTypeIdentifier(), namespace, issuer.Name),
			Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageClientAuth},
		},
	}
}

// approveCSR adds the Approved condition through the "approval" subresource,
// as an approver with cluster-admin rights would.
func approveCSR(t *testing.T, ctx context.Context, kc kubernetes.Interface, csr *certificatesv1.CertificateSigningRequest) {
	t.Helper()

	csr = csr.DeepCopy()
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:           certificatesv1.CertificateApproved,
		Status:         corev1.ConditionTrue,
		Reason:         "ApprovedReason",
		Message:        "ApprovedMessage",
		LastUpdateTime: metav1.Now(),
	})

	_, err := kc.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
	require.NoError(t, err)
}

// impersonatingClientset returns a clientset that acts as the given user. The
// envtest admin credentials are allowed to impersonate anyone.
func impersonatingClientset(t *testing.T, base *rest.Config, username string) kubernetes.Interface {
	t.Helper()

	cfg := rest.CopyConfig(base)
	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: username,
	}

	kc, err := kubernetes.NewForConfig(cfg)
	require.NoError(t, err)
	return kc
}

// grantClusterWideCSRCreate lets the user create and read CSRs. Without this
// the impersonated create call is rejected before the controller ever sees it.
func grantClusterWideCSRCreate(t *testing.T, ctx context.Context, kc kubernetes.Interface, username string) {
	t.Helper()

	name := fmt.Sprintf("%s-csr-creator", username)

	_, err := kc.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{certificatesv1.GroupName},
				Resources: []string{"certificatesigningrequests"},
				Verbs:     []string{"create", "get", "list", "watch"},
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = kc.RbacV1().ClusterRoles().Delete(context.WithoutCancel(ctx), name, metav1.DeleteOptions{})
	})

	_, err = kc.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: username},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     name,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = kc.RbacV1().ClusterRoleBindings().Delete(context.WithoutCancel(ctx), name, metav1.DeleteOptions{})
	})
}

// grantInNamespace binds a Role with the given rule to the user in the given
// namespace. The Role and RoleBinding are garbage collected with the namespace.
func grantInNamespace(t *testing.T, ctx context.Context, kc kubernetes.Interface, namespace, username string, rule rbacv1.PolicyRule) {
	t.Helper()

	name := fmt.Sprintf("%s-signer-reference", username)

	_, err := kc.RbacV1().Roles(namespace).Create(ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Rules:      []rbacv1.PolicyRule{rule},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = kc.RbacV1().RoleBindings(namespace).Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: username},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     name,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
}

// selfSignedCertificatePEM returns a PEM encoded certificate. The API server
// validates that status.certificate holds parseable PEM certificates, so the
// Sign stub cannot return arbitrary bytes.
func selfSignedCertificatePEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "issuer-lib-integration-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
