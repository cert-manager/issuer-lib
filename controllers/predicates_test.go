/*
Copyright 2023 The cert-manager Authors.

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

package controllers_test

import (
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clocktesting "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/internal/testapi/api"
	"github.com/cert-manager/issuer-lib/internal/testapi/testutil"
)

func TestCertificateRequestPredicate(t *testing.T) {
	predicate := controllers.CertificateRequestPredicate{}

	cr1 := cmgen.CertificateRequest("cr1")

	type testcase struct {
		name            string
		event           event.UpdateEvent
		shouldReconcile bool
	}

	testcases := []testcase{
		{
			name:            "nil",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cr1,
				ObjectNew: nil,
			},
		},
		{
			name:            "wrong-type",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cr1,
				ObjectNew: &corev1.ConfigMap{},
			},
		},
		{
			name:            "label-changed",
			shouldReconcile: false,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateRequestFrom(cr1,
					func(cr *cmapi.CertificateRequest) {
						cr.Labels = map[string]string{
							"test-label1": "value",
						}
					},
					cmgen.AddCertificateRequestAnnotations(map[string]string{
						"test-annotation1": "value1",
					}),
				),
				ObjectNew: cmgen.CertificateRequestFrom(cr1,
					cmgen.AddCertificateRequestAnnotations(map[string]string{
						"test-annotation1": "value1",
					}),
				),
			},
		},
		{
			name:            "annotation-added",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateRequestFrom(cr1,
					cmgen.AddCertificateRequestAnnotations(map[string]string{
						"test-annotation1": "value1",
					}),
				),
				ObjectNew: cmgen.CertificateRequestFrom(cr1,
					cmgen.AddCertificateRequestAnnotations(map[string]string{
						"test-annotation1": "value1",
						"test-annotation2": "value2",
					}),
				),
			},
		},
		{
			name:            "ready-condition-changed",
			shouldReconcile: false,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Reason: cmapi.CertificateRequestReasonPending,
						Status: cmmeta.ConditionFalse,
					}),
				),
				ObjectNew: cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Reason: cmapi.CertificateRequestReasonIssued,
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
		},
		{
			name:            "ready-condition-added",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateRequestFrom(cr1),
				ObjectNew: cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Reason: cmapi.CertificateRequestReasonIssued,
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
		},
		{
			name:            "ready-condition-added-other-removed",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Reason: "",
						Status: cmmeta.ConditionFalse,
					}),
				),
				ObjectNew: cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Reason: "",
						Status: cmmeta.ConditionFalse,
					}),
				),
			},
		},
		{
			name:            "approved-condition-changed",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Reason: "",
						Status: cmmeta.ConditionFalse,
					}),
				),
				ObjectNew: cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Reason: "",
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
		},
		{
			name:            "approved-condition-changed-only-reason",
			shouldReconcile: false,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Reason: "test1",
						Status: cmmeta.ConditionFalse,
					}),
				),
				ObjectNew: cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Reason: "test2",
						Status: cmmeta.ConditionFalse,
					}),
				),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result := predicate.Update(tc.event)
			require.Equal(t, tc.shouldReconcile, result)
		})
	}
}

func TestCertificateSigningRequestPredicate(t *testing.T) {
	predicate := controllers.CertificateSigningRequestPredicate{}

	csr1 := cmgen.CertificateSigningRequest("cr1")

	type testcase struct {
		name            string
		event           event.UpdateEvent
		shouldReconcile bool
	}

	testcases := []testcase{
		{
			name:            "nil",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: csr1,
				ObjectNew: nil,
			},
		},
		{
			name:            "wrong-type",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: csr1,
				ObjectNew: &corev1.ConfigMap{},
			},
		},
		{
			name:            "label-changed",
			shouldReconcile: false,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateSigningRequestFrom(csr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Labels = map[string]string{
							"test-label1": "value",
						}
					},
					cmgen.AddCertificateSigningRequestAnnotations(map[string]string{
						"test-annotation1": "value1",
					}),
				),
				ObjectNew: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.AddCertificateSigningRequestAnnotations(map[string]string{
						"test-annotation1": "value1",
					}),
				),
			},
		},
		{
			name:            "annotation-added",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.AddCertificateSigningRequestAnnotations(map[string]string{
						"test-annotation1": "value1",
					}),
				),
				ObjectNew: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.AddCertificateSigningRequestAnnotations(map[string]string{
						"test-annotation1": "value1",
						"test-annotation2": "value2",
					}),
				),
			},
		},
		{
			name:            "failed-condition-changed",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateFailed,
						Reason: cmapi.CertificateRequestReasonPending,
						Status: corev1.ConditionFalse,
					}),
				),
				ObjectNew: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateFailed,
						Reason: cmapi.CertificateRequestReasonIssued,
						Status: corev1.ConditionTrue,
					}),
				),
			},
		},
		{
			name:            "failed-condition-added",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateSigningRequestFrom(csr1),
				ObjectNew: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateFailed,
						Reason: cmapi.CertificateRequestReasonIssued,
						Status: corev1.ConditionTrue,
					}),
				),
			},
		},
		{
			name:            "failed-condition-added-other-removed",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Reason: "",
						Status: corev1.ConditionTrue,
					}),
				),
				ObjectNew: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateFailed,
						Reason: "",
						Status: corev1.ConditionTrue,
					}),
				),
			},
		},
		{
			name:            "approved-condition-changed",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Reason: "",
						Status: corev1.ConditionFalse,
					}),
				),
				ObjectNew: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Reason: "",
						Status: corev1.ConditionTrue,
					}),
				),
			},
		},
		{
			name:            "approved-condition-changed-only-reason",
			shouldReconcile: false,
			event: event.UpdateEvent{
				ObjectOld: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Reason: "test1",
						Status: corev1.ConditionTrue,
					}),
				),
				ObjectNew: cmgen.CertificateSigningRequestFrom(csr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Reason: "test2",
						Status: corev1.ConditionTrue,
					}),
				),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result := predicate.Update(tc.event)
			require.Equal(t, tc.shouldReconcile, result)
		})
	}
}

type testissuer struct {
	Status *v1alpha1.IssuerStatus
	metav1.Object
}

var _ v1alpha1.Issuer = &testissuer{}

func (*testissuer) GetObjectKind() schema.ObjectKind {
	panic("not implemented")
}

func (*testissuer) DeepCopyObject() runtime.Object {
	panic("not implemented")
}

func (ti *testissuer) GetStatus() *v1alpha1.IssuerStatus {
	return ti.Status
}

func TestLinkedIssuerPredicate(t *testing.T) {
	predicate := controllers.LinkedIssuerPredicate{}

	issuer1 := testutil.TestIssuer("issuer-1")

	fakeTime := time.Now()
	fakeClock := clocktesting.NewFakeClock(fakeTime)

	type testcase struct {
		name            string
		event           event.UpdateEvent
		shouldReconcile bool
	}

	testcases := []testcase{
		{
			name:            "nil",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: nil,
				ObjectNew: issuer1,
			},
		},
		{
			name:            "random-condition-changed",
			shouldReconcile: false,
			event: event.UpdateEvent{
				ObjectOld: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						"random",
						cmmeta.ConditionFalse,
						"test1",
						"test1",
					),
				),
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						"random",
						cmmeta.ConditionTrue,
						"test2",
						"test2",
					),
				),
			},
		},
		{
			name:            "ready-status-nil",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: &testissuer{Status: nil},
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						"reason",
						"message",
					),
				),
			},
		},
		{
			name:            "ready-condition-added",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: testutil.TestIssuerFrom(issuer1),
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						"reason",
						"message",
					),
				),
			},
		},
		{
			name:            "ready-condition-identical",
			shouldReconcile: false,
			event: event.UpdateEvent{
				ObjectOld: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						"reason1",
						"message1",
					),
				),
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						"reason2",
						"message2",
					),
				),
			},
		},
		{
			name:            "ready-condition-identical-new-observed-generation",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						"reason1",
						"message1",
					),
				),
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(2),
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						"reason2",
						"message2",
					),
				),
			},
		},
		{
			name:            "ready-condition-changed",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						"reason",
						"message",
					),
				),
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionTrue,
						"reason",
						"message",
					),
				),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result := predicate.Update(tc.event)
			require.Equal(t, tc.shouldReconcile, result)
		})
	}
}

func TestIssuerPredicate(t *testing.T) {
	predicate := controllers.IssuerPredicate{}

	issuer1 := testutil.TestIssuer("issuer-1")

	fakeTime := time.Now()
	fakeClock := clocktesting.NewFakeClock(fakeTime)

	type testcase struct {
		name            string
		event           event.UpdateEvent
		shouldReconcile bool
	}

	testcases := []testcase{
		{
			name:            "nil",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: nil,
				ObjectNew: issuer1,
			},
		},
		{
			name:            "wrong-type",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: issuer1,
				ObjectNew: &corev1.ConfigMap{},
			},
		},
		{
			name:            "identical-generations",
			shouldReconcile: false,
			event: event.UpdateEvent{
				ObjectOld: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
				),
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
				),
			},
		},
		{
			name:            "changed-generations",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
				),
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(2),
				),
			},
		},
		{
			name:            "changed-annotations",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
					func(si *api.TestIssuer) {
						si.SetAnnotations(map[string]string{
							"test-annotation": "test",
						})
					},
				),
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
				),
			},
		},
		{
			name:            "ready-condition-added",
			shouldReconcile: true,
			event: event.UpdateEvent{
				ObjectOld: testutil.TestIssuerFrom(issuer1),
				ObjectNew: testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						"reason",
						"message",
					),
				),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result := predicate.Update(tc.event)
			require.Equal(t, tc.shouldReconcile, result)
		})
	}
}
