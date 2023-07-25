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

package controllers

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	clocktesting "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/kubeutil"
	"github.com/cert-manager/issuer-lib/internal/tests/errormatch"
	"github.com/cert-manager/issuer-lib/internal/tests/ptr"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/api"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/testutil"
)

func TestCertificateRequestReconcilerReconcile(t *testing.T) {
	t.Parallel()

	fieldOwner := "test-certificate-request-reconciler-reconcile"

	type testCase struct {
		name                string
		sign                signer.Sign
		objects             []client.Object
		validateError       *errormatch.Matcher
		expectedResult      reconcile.Result
		expectedStatusPatch *cmapi.CertificateRequestStatus
		expectedEvents      []string
	}

	randTime := randomTime()

	fakeTime1 := randTime.Truncate(time.Second)
	fakeTimeObj1 := metav1.NewTime(fakeTime1)
	fakeClock1 := clocktesting.NewFakeClock(fakeTime1)

	fakeTime2 := randTime.Add(4 * time.Hour).Truncate(time.Second)
	fakeTimeObj2 := metav1.NewTime(fakeTime2)
	fakeClock2 := clocktesting.NewFakeClock(fakeTime2)

	issuer1 := testutil.SimpleIssuer(
		"issuer-1",
		testutil.SetSimpleIssuerNamespace("ns1"),
		testutil.SetSimpleIssuerGeneration(70),
		testutil.SetSimpleIssuerStatusCondition(
			fakeClock1,
			cmapi.IssuerConditionReady,
			cmmeta.ConditionTrue,
			v1alpha1.IssuerConditionReasonChecked,
			"checked",
		),
	)

	clusterIssuer1 := testutil.SimpleClusterIssuer(
		"cluster-issuer-1",
		testutil.SetSimpleClusterIssuerGeneration(70),
		testutil.SetSimpleClusterIssuerStatusCondition(
			fakeClock1,
			cmapi.IssuerConditionReady,
			cmmeta.ConditionTrue,
			v1alpha1.IssuerConditionReasonChecked,
			"checked",
		),
	)

	cr1 := cmgen.CertificateRequest(
		"cr1",
		cmgen.SetCertificateRequestNamespace("ns1"),
		cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Group: api.SchemeGroupVersion.Group,
		}),
		func(cr *cmapi.CertificateRequest) {
			conditions.SetCertificateRequestStatusCondition(
				fakeClock1,
				cr.Status.Conditions,
				&cr.Status.Conditions,
				cmapi.CertificateRequestConditionReady,
				cmmeta.ConditionUnknown,
				v1alpha1.CertificateRequestConditionReasonInitializing,
				fieldOwner+" has begun reconciling this CertificateRequest",
			)
			conditions.SetCertificateRequestStatusCondition(
				fakeClock1,
				cr.Status.Conditions,
				&cr.Status.Conditions,
				cmapi.CertificateRequestConditionApproved,
				cmmeta.ConditionTrue,
				"ApprovedReason",
				"ApprovedMessage",
			)
		},
	)

	successSigner := func(cert string) signer.Sign {
		return func(_ context.Context, _ signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
			return signer.PEMBundle{
				ChainPEM: []byte(cert),
			}, nil
		}
	}

	tests := []testCase{
		// NOTE: The IssuerError error cannot be tested in this unit test. It is tested in the
		// integration test instead.

		// Ignore the request if the CertificateRequest is not found.
		{
			name:    "ignore-certificaterequest-not-found",
			objects: []client.Object{},
		},

		// Ignore unless approved or denied.
		{
			name: "ignore-unless-approved-or-denied",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1, func(cr *cmapi.CertificateRequest) {
					cr.Status.Conditions = nil
				}),
			},
		},

		// Ignore CertificateRequest with an unknown issuerRef group.
		{
			name: "issuer-ref-unknown-group",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1, func(cr *cmapi.CertificateRequest) {
					cr.Spec.IssuerRef.Group = "unknown-group"
				}),
			},
		},

		// Ignore CertificateRequest with an unknown issuerRef kind.
		{
			name: "issuer-ref-unknown-kind",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1, func(cr *cmapi.CertificateRequest) {
					cr.Spec.IssuerRef.Kind = "unknown-kind"
				}),
			},
		},

		// Ignore CertificateRequest which is already Ready.
		{
			name: "already-ready",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Reason: cmapi.CertificateRequestReasonIssued,
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
		},

		// Ignore CertificateRequest which is already Failed.
		{
			name: "already-failed",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionFalse,
						Reason: cmapi.CertificateRequestReasonFailed,
					}),
				),
			},
		},

		// Ignore CertificateRequest which is already Denied.
		{
			name: "already-denied",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionFalse,
						Reason: cmapi.CertificateRequestReasonDenied,
					}),
				),
			},
		},

		// Initialize the CertificateRequest Ready condition if it is missing.
		{
			name: "initialize-ready-condition",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1, func(cr *cmapi.CertificateRequest) {
					removeCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady)
				}),
			},
			expectedResult: reconcile.Result{},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionUnknown,
						Reason:             v1alpha1.CertificateRequestConditionReasonInitializing,
						Message:            fieldOwner + " has started reconciling this CertificateRequest",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
		},

		// If denied, set Ready condition status to false and reason to denied.
		{
			name: "set-ready-denied",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1, cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:   cmapi.CertificateRequestConditionDenied,
					Status: cmmeta.ConditionTrue,
					Reason: "",
				})),
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonDenied,
						Message:            "The CertificateRequest was denied by an approval controller",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
				FailureTime: &fakeTimeObj2,
			},
			expectedEvents: []string{
				"Normal DetectedDenied Detected that the CR is denied, will update Ready condition",
			},
		},

		// If issuer is missing, set Ready condition status to false and reason to pending.
		{
			name: "set-ready-pending-missing-issuer",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1, func(cr *cmapi.CertificateRequest) {
					cr.Spec.IssuerRef.Name = issuer1.Name
					cr.Spec.IssuerRef.Kind = issuer1.Kind
				}),
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonPending,
						Message:            "simpleissuers.testing.cert-manager.io \"issuer-1\" not found. Waiting for it to be created.",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Normal WaitingForIssuerExist Waiting for the issuer to exist",
			},
		},

		// If issuer has no ready condition, set Ready condition status to false and reason to
		// pending.
		{
			name: "set-ready-pending-issuer-has-no-ready-condition",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
				),
				testutil.SimpleIssuerFrom(issuer1,
					func(si *api.SimpleIssuer) {
						si.Status.Conditions = nil
					},
				),
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonPending,
						Message:            "Issuer is not Ready yet. No ready condition found. Waiting for it to become ready.",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Normal WaitingForIssuerReady Waiting for the issuer to become ready",
			},
		},

		// If issuer is not ready, set Ready condition status to false and reason to pending.
		{
			name: "set-ready-pending-issuer-is-not-ready",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
				),
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerStatusCondition(
						fakeClock1,
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						"[REASON]",
						"[MESSAGE]",
					),
				),
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonPending,
						Message:            "Issuer is not Ready yet. Current ready condition is \"[REASON]\": [MESSAGE]. Waiting for it to become ready.",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Normal WaitingForIssuerReady Waiting for the issuer to become ready",
			},
		},

		// If issuer's ready condition is outdated, set Ready condition status to false and reason
		// to pending.
		{
			name: "set-ready-pending-issuer-ready-outdated",
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
				),
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerGeneration(issuer1.Generation+1),
				),
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonPending,
						Message:            "Issuer is not Ready yet. Current ready condition is outdated. Waiting for it to become ready.",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Normal WaitingForIssuerReady Waiting for the issuer to become ready",
			},
		},

		// If the sign function returns an error & it's too late for a retry, set the Ready
		// condition to Failed.
		{
			name: "timeout-permanent-error",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, fmt.Errorf("a specific error")
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
					func(cr *cmapi.CertificateRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateRequest has failed permanently: a specific error",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
				FailureTime: &fakeTimeObj2,
			},
			expectedEvents: []string{
				"Warning PermanentError Failed permanently to sign CertificateRequest: a specific error",
			},
		},

		// If the sign function returns a Pending error, set the Ready condition to Pending (even if
		// the MaxRetryDuration has been exceeded).
		{
			name: "retry-on-pending-error",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, signer.PendingError{Err: fmt.Errorf("pending error")}
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
					func(cr *cmapi.CertificateRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			// instead of returning an error, we trigger a new reconciliation by setting requeue=true
			validateError: errormatch.NoError(),
			expectedResult: reconcile.Result{
				Requeue: true,
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonPending,
						Message:            "CertificateRequest is not ready yet: pending error",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Warning RetryableError Failed to sign CertificateRequest, will retry: pending error",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError error with a condition
		// type that is *not present* in the status, the new condition is *added* to the
		// CertificateRequest.
		// Additionally, if the error wrapped by SetCertificateRequestConditionError is not one of the
		// supported 'signer API' errors an we still *have time left* to retry, set the Ready
		// condition to *Pending*.
		{
			name: "error-set-certificate-request-condition-should-add-new-condition-and-retry",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, signer.SetCertificateRequestConditionError{
					Err:           fmt.Errorf("test error"),
					ConditionType: "[condition type]",
					Status:        cmmeta.ConditionTrue,
					Reason:        "[reason]",
				}
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					func(cr *cmapi.CertificateRequest) {
						cr.CreationTimestamp = fakeTimeObj2
					},
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			// no error should be returned because the reconciliation should be triggered
			// when the custom condition is added
			validateError: errormatch.NoError(),
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               "[condition type]",
						Status:             cmmeta.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: &fakeTimeObj2,
					},
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonPending,
						Message:            "CertificateRequest is not ready yet: test error",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Warning RetryableError Failed to sign CertificateRequest, will retry: test error",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError error with a condition
		// type that is *already present* in the status, the existing condition is *updated* with
		// the values specified in the error.
		// Additionally, if the error wrapped by SetCertificateRequestConditionError is not one of the
		// supported 'signer API' errors an we still *have time left* to retry, set the Ready
		// condition to *Pending*.
		{
			name: "error-set-certificate-request-condition-should-update-existing-condition-and-retry",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, signer.SetCertificateRequestConditionError{
					Err:           fmt.Errorf("test error2"),
					ConditionType: "[condition type]",
					Status:        cmmeta.ConditionTrue,
					Reason:        "[reason]",
				}
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					func(cr *cmapi.CertificateRequest) {
						cr.CreationTimestamp = fakeTimeObj2
					},
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
					cmgen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:               "[condition type]",
						Status:             cmmeta.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: &fakeTimeObj2,
					}),
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			// instead of returning an error, we trigger a new reconciliation by setting requeue=true
			validateError: errormatch.NoError(),
			expectedResult: reconcile.Result{
				Requeue: true,
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               "[condition type]",
						Status:             cmmeta.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error2",
						LastTransitionTime: &fakeTimeObj2,
					},
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonPending,
						Message:            "CertificateRequest is not ready yet: test error2",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Warning RetryableError Failed to sign CertificateRequest, will retry: test error2",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError error with a condition
		// type that is *not present* in the status, the new condition is *added* to the
		// CertificateRequest.
		// Additionally, if the error wrapped by SetCertificateRequestConditionError is not one of the
		// supported 'signer API' errors an we have *no time left* to retry, set the Ready condition
		// to *Failed*.
		{
			name: "error-set-certificate-request-condition-should-add-new-condition-and-timeout",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, signer.SetCertificateRequestConditionError{
					Err:           fmt.Errorf("test error"),
					ConditionType: "[condition type]",
					Status:        cmmeta.ConditionTrue,
					Reason:        "[reason]",
				}
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
					func(cr *cmapi.CertificateRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			// no error should be returned because the reconciliation should be triggered when the
			// custom condition is added
			validateError: errormatch.NoError(),
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               "[condition type]",
						Status:             cmmeta.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: &fakeTimeObj2,
					},
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateRequest has failed permanently: test error",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
				FailureTime: &fakeTimeObj2,
			},
			expectedEvents: []string{
				"Warning PermanentError Failed permanently to sign CertificateRequest: test error",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError error with a condition
		// type that is *already present* in the status, the existing condition is *updated* with
		// the values specified in the error.
		// Additionally, if the error wrapped by SetCertificateRequestConditionError is not one of the
		// supported 'signer API' errors an we have *no time left* to retry, set the Ready condition
		// to *Failed*.
		{
			name: "error-set-certificate-request-condition-should-update-existing-condition-and-timeout",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, signer.SetCertificateRequestConditionError{
					Err:           fmt.Errorf("test error2"),
					ConditionType: "[condition type]",
					Status:        cmmeta.ConditionTrue,
					Reason:        "[reason]",
				}
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
					func(cr *cmapi.CertificateRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
					cmgen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:               "[condition type]",
						Status:             cmmeta.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: &fakeTimeObj1,
					}),
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			// since we got into a permanent failure state, we should not return an error
			validateError: errormatch.NoError(),
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               "[condition type]",
						Status:             cmmeta.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error2",
						LastTransitionTime: &fakeTimeObj1, // since the status is not updated, the LastTransitionTime is not updated either
					},
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateRequest has failed permanently: test error2",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
				FailureTime: &fakeTimeObj2,
			},
			expectedEvents: []string{
				"Warning PermanentError Failed permanently to sign CertificateRequest: test error2",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError, the specified
		// conditions value is updated/ added to the CertificateRequest status.
		// Additionally, if the error wrapped by SetCertificateRequestConditionError is a PendingError
		// error, the Ready condition is set to Pending (even if the MaxRetryDuration has been
		// exceeded).
		{
			name: "error-set-certificate-request-condition-should-not-timeout-if-pending",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, signer.SetCertificateRequestConditionError{
					Err:           signer.PendingError{Err: fmt.Errorf("test error")},
					ConditionType: "[condition type]",
					Status:        cmmeta.ConditionTrue,
					Reason:        "[reason]",
				}
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
					func(cr *cmapi.CertificateRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			// no error should be returned because the reconciliation should be triggered
			// when the custom condition is added
			validateError: errormatch.NoError(),
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               "[condition type]",
						Status:             cmmeta.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: &fakeTimeObj2,
					},
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonPending,
						Message:            "CertificateRequest is not ready yet: test error",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Warning RetryableError Failed to sign CertificateRequest, will retry: test error",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError, the specified
		// conditions value is updated/ added to the CertificateRequest status.
		// Additionally, if the error wrapped by SetCertificateRequestConditionError is a PendingError
		// error, the Ready condition is set to Failed (even if the MaxRetryDuration has NOT been
		// exceeded).
		{
			name: "error-set-certificate-request-condition-should-not-retry-on-permanent-error",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, signer.SetCertificateRequestConditionError{
					Err:           signer.PermanentError{Err: fmt.Errorf("test error")},
					ConditionType: "[condition type]",
					Status:        cmmeta.ConditionTrue,
					Reason:        "[reason]",
				}
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			// no error should be returned because we are in a permanent failure state no further
			// retries should be made
			validateError: errormatch.NoError(),
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               "[condition type]",
						Status:             cmmeta.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: &fakeTimeObj2,
					},
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateRequest has failed permanently: test error",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
				FailureTime: &fakeTimeObj2,
			},
			expectedEvents: []string{
				"Warning PermanentError Failed permanently to sign CertificateRequest: test error",
			},
		},

		// Set the Ready condition to Failed if the sign function returns a permanent error.
		{
			name: "fail-on-permanent-error",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, signer.PermanentError{Err: fmt.Errorf("a specific error")}
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  issuer1.Name,
						Group: api.SchemeGroupVersion.Group,
					}),
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateRequest has failed permanently: a specific error",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
				FailureTime: &fakeTimeObj2,
			},
			expectedEvents: []string{
				"Warning PermanentError Failed permanently to sign CertificateRequest: a specific error",
			},
		},

		// Set the Ready condition to Pending if sign returns an error and we still have time left
		// to retry.
		{
			name: "retry-on-error",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, errors.New("waiting for approval")
			},
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1,
					func(cr *cmapi.CertificateRequest) {
						cr.CreationTimestamp = fakeTimeObj2
					},
					func(cr *cmapi.CertificateRequest) {
						cr.Spec.IssuerRef.Name = issuer1.Name
						cr.Spec.IssuerRef.Kind = issuer1.Kind
					},
				),
				testutil.SimpleIssuerFrom(issuer1),
			},
			// instead of returning an error, we trigger a new reconciliation by setting requeue=true
			validateError: errormatch.NoError(),
			expectedResult: reconcile.Result{
				Requeue: true,
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             cmapi.CertificateRequestReasonPending,
						Message:            "CertificateRequest is not ready yet: waiting for approval",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Warning RetryableError Failed to sign CertificateRequest, will retry: waiting for approval",
			},
		},

		{
			name: "success-issuer",
			sign: successSigner("a-signed-certificate"),
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1, func(cr *cmapi.CertificateRequest) {
					cr.Spec.IssuerRef.Name = issuer1.Name
					cr.Spec.IssuerRef.Kind = issuer1.Kind
				}),
				testutil.SimpleIssuerFrom(issuer1),
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Certificate: []byte("a-signed-certificate"),
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionTrue,
						Reason:             cmapi.CertificateRequestReasonIssued,
						Message:            "issued",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Normal Issued Succeeded signing the CertificateRequest",
			},
		},

		{
			name: "success-clusterissuer",
			sign: successSigner("a-signed-certificate"),
			objects: []client.Object{
				cmgen.CertificateRequestFrom(cr1, func(cr *cmapi.CertificateRequest) {
					cr.Spec.IssuerRef.Name = clusterIssuer1.Name
					cr.Spec.IssuerRef.Kind = clusterIssuer1.Kind
				}),
				testutil.SimpleClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &cmapi.CertificateRequestStatus{
				Certificate: []byte("a-signed-certificate"),
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionTrue,
						Reason:             cmapi.CertificateRequestReasonIssued,
						Message:            "issued",
						LastTransitionTime: &fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Normal Issued Succeeded signing the CertificateRequest",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scheme := runtime.NewScheme()
			require.NoError(t, setupCertificateRequestReconcilerScheme(scheme))
			require.NoError(t, api.AddToScheme(scheme))
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.objects...).
				Build()

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      cr1.Name,
					Namespace: cr1.Namespace,
				},
			}

			var crBefore cmapi.CertificateRequest
			err := fakeClient.Get(context.TODO(), req.NamespacedName, &crBefore)
			require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")

			logger := logrtesting.NewTestLoggerWithOptions(t, logrtesting.Options{LogTimestamp: true, Verbosity: 10})
			fakeRecorder := record.NewFakeRecorder(100)

			controller := CertificateRequestReconciler{
				IssuerTypes:        []v1alpha1.Issuer{&api.SimpleIssuer{}},
				ClusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleClusterIssuer{}},
				FieldOwner:         fieldOwner,
				MaxRetryDuration:   time.Minute,
				EventSource:        kubeutil.NewEventStore(),
				Client:             fakeClient,
				Sign:               tc.sign,
				EventRecorder:      fakeRecorder,
				Clock:              fakeClock2,
			}

			err = controller.setIssuersGroupVersionKind(scheme)
			require.NoError(t, err)

			res, crsPatch, err := controller.reconcileStatusPatch(logger, context.TODO(), req)

			assert.Equal(t, tc.expectedResult, res)
			assert.Equal(t, tc.expectedStatusPatch, crsPatch)
			ptr.Default(tc.validateError, *errormatch.NoError())(t, err)

			allEvents := chanToSlice(fakeRecorder.Events)
			if len(tc.expectedEvents) == 0 {
				assert.Emptyf(t, allEvents, "expected no events to be recorded, but got: %#v", allEvents)
			} else {
				assert.Equal(t, tc.expectedEvents, allEvents)
			}
		})
	}
}

func chanToSlice(ch <-chan string) []string {
	out := make([]string, 0, len(ch))
	for i := 0; i < len(ch); i++ {
		out = append(out, <-ch)
	}
	return out
}

func removeCertificateRequestCondition(cr *cmapi.CertificateRequest, conditionType cmapi.CertificateRequestConditionType) {
	for i, cond := range cr.Status.Conditions {
		if cond.Type == conditionType {
			cr.Status.Conditions = append(cr.Status.Conditions[:i], cr.Status.Conditions[i+1:]...)
			return
		}
	}
}

func TestCertificateRequestMatchIssuerType(t *testing.T) {
	t.Parallel()

	type testcase struct {
		name string

		issuerTypes        []v1alpha1.Issuer
		clusterIssuerTypes []v1alpha1.Issuer
		cr                 *cmapi.CertificateRequest

		expectedIssuerType v1alpha1.Issuer
		expectedIssuerName types.NamespacedName
	}

	createCr := func(name string, namespace string, kind string, group string) *cmapi.CertificateRequest {
		return &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
			},
			Spec: cmapi.CertificateRequestSpec{
				IssuerRef: cmmeta.ObjectReference{
					Name:  name,
					Kind:  kind,
					Group: group,
				},
			},
		}
	}

	testcases := []testcase{
		{
			name:               "empty",
			issuerTypes:        nil,
			clusterIssuerTypes: nil,
			cr:                 nil,

			expectedIssuerType: nil,
			expectedIssuerName: types.NamespacedName{},
		},
		{
			name:               "no issuers",
			issuerTypes:        nil,
			clusterIssuerTypes: nil,
			cr:                 createCr("name", "namespace", "", "test"),

			expectedIssuerType: nil,
			expectedIssuerName: types.NamespacedName{},
		},
		{
			name:               "match issuer",
			issuerTypes:        []v1alpha1.Issuer{&api.SimpleIssuer{}},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleClusterIssuer{}},
			cr:                 createCr("name", "namespace", "SimpleIssuer", "testing.cert-manager.io"),

			expectedIssuerType: &api.SimpleIssuer{},
			expectedIssuerName: types.NamespacedName{Name: "name", Namespace: "namespace"},
		},
		{
			name:               "match cluster issuer",
			issuerTypes:        []v1alpha1.Issuer{&api.SimpleIssuer{}},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleClusterIssuer{}},
			cr:                 createCr("name", "namespace", "SimpleClusterIssuer", "testing.cert-manager.io"),

			expectedIssuerType: &api.SimpleClusterIssuer{},
			expectedIssuerName: types.NamespacedName{Name: "name"},
		},
		{
			name:               "select kind if empty",
			issuerTypes:        []v1alpha1.Issuer{},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleClusterIssuer{}},
			cr:                 createCr("name", "namespace", "", "testing.cert-manager.io"),

			expectedIssuerType: &api.SimpleClusterIssuer{},
			expectedIssuerName: types.NamespacedName{Name: "name"},
		},
		{
			name:               "prefer issuer over cluster issuer (v1)",
			issuerTypes:        []v1alpha1.Issuer{&api.SimpleIssuer{}},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleClusterIssuer{}},
			cr:                 createCr("name", "namespace", "", "testing.cert-manager.io"),

			expectedIssuerType: &api.SimpleIssuer{},
			expectedIssuerName: types.NamespacedName{Name: "name", Namespace: "namespace"},
		},
		{
			name:               "prefer issuer over cluster issuer (v2)",
			issuerTypes:        []v1alpha1.Issuer{&api.SimpleIssuer{}},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleIssuer{}},
			cr:                 createCr("name", "namespace", "", "testing.cert-manager.io"),

			expectedIssuerType: &api.SimpleIssuer{},
			expectedIssuerName: types.NamespacedName{Name: "name", Namespace: "namespace"},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, api.AddToScheme(scheme))

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			crr := &CertificateRequestReconciler{
				IssuerTypes:        tc.issuerTypes,
				ClusterIssuerTypes: tc.clusterIssuerTypes,
			}

			require.NoError(t, crr.setIssuersGroupVersionKind(scheme))

			issuerType, issuerName := crr.matchIssuerType(tc.cr)

			if tc.expectedIssuerType != nil {
				require.NoError(t, kubeutil.SetGroupVersionKind(scheme, tc.expectedIssuerType))
			}

			assert.Equal(t, tc.expectedIssuerType, issuerType)
			assert.Equal(t, tc.expectedIssuerName, issuerName)
		})
	}
}
