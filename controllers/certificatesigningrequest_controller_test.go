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
	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/kubeutil"
	"github.com/cert-manager/issuer-lib/internal/testapi/api"
	"github.com/cert-manager/issuer-lib/internal/testapi/testutil"
	"github.com/cert-manager/issuer-lib/internal/tests/errormatch"
)

func TestCertificateSigningRequestReconcilerReconcile(t *testing.T) {
	t.Parallel()

	fieldOwner := "test-certificate-request-reconciler-reconcile"

	type testCase struct {
		name                string
		sign                signer.Sign
		objects             []client.Object
		validateError       *errormatch.Matcher
		expectedResult      reconcile.Result
		expectedStatusPatch *certificatesv1.CertificateSigningRequestStatus
		expectedEvents      []string
	}

	randTime := randomTime()

	fakeTime1 := randTime.Truncate(time.Second)
	fakeTimeObj1 := metav1.NewTime(fakeTime1)
	fakeClock1 := clocktesting.NewFakeClock(fakeTime1)

	fakeTime2 := randTime.Add(4 * time.Hour).Truncate(time.Second)
	fakeTimeObj2 := metav1.NewTime(fakeTime2)
	fakeClock2 := clocktesting.NewFakeClock(fakeTime2)

	issuer1 := testutil.TestIssuer(
		"issuer-1",
		testutil.SetTestIssuerNamespace("ns1"),
		testutil.SetTestIssuerGeneration(70),
		testutil.SetTestIssuerStatusCondition(
			fakeClock1,
			v1alpha1.IssuerConditionTypeReady,
			metav1.ConditionTrue,
			v1alpha1.IssuerConditionReasonChecked,
			"Succeeded checking the issuer",
		),
	)

	clusterIssuer1 := testutil.TestClusterIssuer(
		"cluster-issuer-1",
		testutil.SetTestClusterIssuerGeneration(70),
		testutil.SetTestClusterIssuerStatusCondition(
			fakeClock1,
			v1alpha1.IssuerConditionTypeReady,
			metav1.ConditionTrue,
			v1alpha1.IssuerConditionReasonChecked,
			"Succeeded checking the issuer",
		),
	)

	cr1 := cmgen.CertificateSigningRequest(
		"cr1",
		cmgen.SetCertificateSigningRequestSignerName("testissuers.testing.cert-manager.io/unknown-namespace.unknown-name"),
		func(cr *certificatesv1.CertificateSigningRequest) {
			conditions.SetCertificateSigningRequestStatusCondition(
				fakeClock1,
				cr.Status.Conditions,
				&cr.Status.Conditions,
				certificatesv1.CertificateApproved,
				v1.ConditionTrue,
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

		// Ignore the request if the CertificateSigningRequest is not found.
		{
			name:    "ignore-certificatesigningrequest-not-found",
			objects: []client.Object{},
		},

		// Ignore unless approved or denied.
		{
			name: "ignore-unless-approved-or-denied",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1, func(cr *certificatesv1.CertificateSigningRequest) {
					cr.Status.Conditions = nil
				}),
			},
		},

		// Ignore CertificateSigningRequest with an unknown SignerName group.
		{
			name: "issuer-ref-unknown-group",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1, func(cr *certificatesv1.CertificateSigningRequest) {
					cr.Spec.SignerName = "testclusterissuers.unknown-group/name"
				}),
			},
		},

		// Ignore CertificateSigningRequest with an unknown SignerName kind.
		{
			name: "issuer-ref-unknown-kind",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1, func(cr *certificatesv1.CertificateSigningRequest) {
					cr.Spec.SignerName = "unknown-kind.testing.cert-manager.io/name"
				}),
			},
		},

		// Ignore CertificateSigningRequest which is already Ready.
		{
			name: "already-ready",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1,
					func(csr *certificatesv1.CertificateSigningRequest) {
						csr.Status.Certificate = []byte("certificate")
					},
				),
			},
		},

		// Ignore CertificateSigningRequest which is already Failed.
		{
			name: "already-failed",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateFailed,
						Status: v1.ConditionTrue,
					}),
				),
			},
		},

		// Ignore CertificateSigningRequest which is already Denied.
		{
			name: "already-denied",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1,
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateDenied,
						Status: v1.ConditionTrue,
					}),
				),
			},
		},

		// If issuer is missing, set Ready condition status to false and reason to pending.
		{
			name: "set-ready-pending-missing-issuer",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1, func(cr *certificatesv1.CertificateSigningRequest) {
					cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
				}),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: nil,
			},
			expectedEvents: []string{
				"Normal WaitingForIssuerExist testclusterissuers.testing.cert-manager.io \"cluster-issuer-1\" not found. Waiting for it to be created.",
			},
		},

		// If issuer has no ready condition, set Ready condition status to false and reason to
		// pending.
		{
			name: "set-ready-pending-issuer-has-no-ready-condition",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1, func(cr *certificatesv1.CertificateSigningRequest) {
					cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
				}),
				testutil.TestClusterIssuerFrom(clusterIssuer1,
					func(si *api.TestClusterIssuer) {
						si.Status.Conditions = nil
					},
				),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: nil,
			},
			expectedEvents: []string{
				"Normal WaitingForIssuerReady Waiting for issuer to become ready. Current issuer ready condition: <none>.",
			},
		},

		// If issuer is not ready, set Ready condition status to false and reason to pending.
		{
			name: "set-ready-pending-issuer-is-not-ready",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1, func(cr *certificatesv1.CertificateSigningRequest) {
					cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
				}),
				testutil.TestClusterIssuerFrom(clusterIssuer1,
					testutil.SetTestClusterIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionFalse,
						"[REASON]",
						"[MESSAGE]",
					),
				),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: nil,
			},
			expectedEvents: []string{
				"Normal WaitingForIssuerReady Waiting for issuer to become ready. Current issuer ready condition is \"[REASON]\": [MESSAGE].",
			},
		},

		// If issuer's ready condition is outdated, set Ready condition status to false and reason
		// to pending.
		{
			name: "set-ready-pending-issuer-ready-outdated",
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1, func(cr *certificatesv1.CertificateSigningRequest) {
					cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
				}),
				testutil.TestClusterIssuerFrom(clusterIssuer1,
					testutil.SetTestClusterIssuerGeneration(issuer1.Generation+1),
				),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: nil,
			},
			expectedEvents: []string{
				"Normal WaitingForIssuerReady Waiting for issuer to become ready. Current issuer ready condition is outdated.",
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
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{
					{
						Type:               certificatesv1.CertificateFailed,
						Status:             v1.ConditionTrue,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateSigningRequest has failed permanently: a specific error",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("terminal error: a specific error"),
			expectedEvents: []string{
				"Warning PermanentError CertificateSigningRequest has failed permanently: a specific error",
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
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: nil,
			},
			expectedResult: reconcile.Result{
				Requeue: true,
			},
			expectedEvents: []string{
				"Warning Pending Signing still in progress. Reason: Signing still in progress. Reason: pending error",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError error with a condition
		// type that is *not present* in the status, the new condition is *added* to the
		// CertificateSigningRequest.
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
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.CreationTimestamp = fakeTimeObj2
					},
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{
					{
						Type:               "[condition type]",
						Status:             v1.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("terminal error: test error"),
			expectedEvents: []string{
				"Warning RetryableError Failed to sign CertificateSigningRequest, will retry: test error",
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
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.CreationTimestamp = fakeTimeObj2
					},
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:               "[condition type]",
						Status:             v1.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					}),
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{
					{
						Type:               "[condition type]",
						Status:             v1.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error2",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("test error2"),
			expectedEvents: []string{
				"Warning RetryableError Failed to sign CertificateSigningRequest, will retry: test error2",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError error with a condition
		// type that is *not present* in the status, the new condition is *added* to the
		// CertificateSigningRequest.
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
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{
					{
						Type:               "[condition type]",
						Status:             v1.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
					{
						Type:               certificatesv1.CertificateFailed,
						Status:             v1.ConditionTrue,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateSigningRequest has failed permanently: test error",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("terminal error: test error"),
			expectedEvents: []string{
				"Warning PermanentError CertificateSigningRequest has failed permanently: test error",
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
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:               "[condition type]",
						Status:             v1.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: fakeTimeObj1,
						LastUpdateTime:     fakeTimeObj1,
					}),
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{
					{
						Type:               "[condition type]",
						Status:             v1.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error2",
						LastTransitionTime: fakeTimeObj1, // since the status is not updated, the LastTransitionTime is not updated either
						LastUpdateTime:     fakeTimeObj2,
					},
					{
						Type:               certificatesv1.CertificateFailed,
						Status:             v1.ConditionTrue,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateSigningRequest has failed permanently: test error2",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("terminal error: test error2"),
			expectedEvents: []string{
				"Warning PermanentError CertificateSigningRequest has failed permanently: test error2",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError, the specified
		// conditions value is updated/ added to the CertificateSigningRequest status.
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
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.CreationTimestamp = metav1.NewTime(fakeTimeObj2.Add(-2 * time.Minute))
					},
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{
					{
						Type:               "[condition type]",
						Status:             v1.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
				},
			},
			expectedResult: reconcile.Result{
				Requeue: false,
			},
			expectedEvents: []string{
				"Warning Pending Signing still in progress. Reason: Signing still in progress. Reason: test error",
			},
		},

		// If the sign function returns an SetCertificateRequestConditionError, the specified
		// conditions value is updated/ added to the CertificateSigningRequest status.
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
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{
					{
						Type:               "[condition type]",
						Status:             v1.ConditionTrue,
						Reason:             "[reason]",
						Message:            "test error",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
					{
						Type:               certificatesv1.CertificateFailed,
						Status:             v1.ConditionTrue,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateSigningRequest has failed permanently: test error",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("terminal error: test error"),
			expectedEvents: []string{
				"Warning PermanentError CertificateSigningRequest has failed permanently: test error",
			},
		},

		// Set the Ready condition to Failed if the sign function returns a permanent error.
		{
			name: "fail-on-permanent-error",
			sign: func(_ context.Context, cr signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, error) {
				return signer.PEMBundle{}, signer.PermanentError{Err: fmt.Errorf("a specific error")}
			},
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{
					{
						Type:               certificatesv1.CertificateFailed,
						Status:             v1.ConditionTrue,
						Reason:             cmapi.CertificateRequestReasonFailed,
						Message:            "CertificateSigningRequest has failed permanently: a specific error",
						LastTransitionTime: fakeTimeObj2,
						LastUpdateTime:     fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("terminal error: a specific error"),
			expectedEvents: []string{
				"Warning PermanentError CertificateSigningRequest has failed permanently: a specific error",
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
				cmgen.CertificateSigningRequestFrom(cr1,
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
					},
					func(cr *certificatesv1.CertificateSigningRequest) {
						cr.CreationTimestamp = fakeTimeObj2
					},
				),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Conditions: nil,
			},
			validateError: errormatch.ErrorContains("waiting for approval"),
			expectedEvents: []string{
				"Warning RetryableError Failed to sign CertificateSigningRequest, will retry: waiting for approval",
			},
		},

		{
			name: "success-issuer",
			sign: successSigner("a-signed-certificate"),
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1, func(cr *certificatesv1.CertificateSigningRequest) {
					cr.Spec.SignerName = fmt.Sprintf("%s/%s.%s", issuer1.GetIssuerTypeIdentifier(), issuer1.Namespace, issuer1.Name)
				}),
				testutil.TestIssuerFrom(issuer1),
			},
			expectedStatusPatch: nil,
			expectedEvents:      []string{},
		},

		{
			name: "success-clusterissuer",
			sign: successSigner("a-signed-certificate"),
			objects: []client.Object{
				cmgen.CertificateSigningRequestFrom(cr1, func(cr *certificatesv1.CertificateSigningRequest) {
					cr.Spec.SignerName = fmt.Sprintf("%s/%s", clusterIssuer1.GetIssuerTypeIdentifier(), clusterIssuer1.Name)
				}),
				testutil.TestClusterIssuerFrom(clusterIssuer1),
			},
			expectedStatusPatch: &certificatesv1.CertificateSigningRequestStatus{
				Certificate: []byte("a-signed-certificate"),
				Conditions:  nil,
			},
			expectedEvents: []string{
				"Normal Issued Succeeded signing the CertificateSigningRequest",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scheme := runtime.NewScheme()
			require.NoError(t, setupCertificateSigningRequestReconcilerScheme(scheme))
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

			var crBefore certificatesv1.CertificateSigningRequest
			err := fakeClient.Get(context.TODO(), req.NamespacedName, &crBefore)
			require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")

			logger := logrtesting.NewTestLoggerWithOptions(t, logrtesting.Options{LogTimestamp: true, Verbosity: 10})
			fakeRecorder := record.NewFakeRecorder(100)

			controller := (&CertificateSigningRequestReconciler{
				RequestController: RequestController{
					IssuerTypes:        []v1alpha1.Issuer{&api.TestIssuer{}},
					ClusterIssuerTypes: []v1alpha1.Issuer{&api.TestClusterIssuer{}},
					FieldOwner:         fieldOwner,
					MaxRetryDuration:   time.Minute,
					EventSource:        kubeutil.NewEventStore(),
					Client:             fakeClient,
					Sign:               tc.sign,
					EventRecorder:      fakeRecorder,
					Clock:              fakeClock2,
				},
			}).Init()

			err = controller.setAllIssuerTypesWithGroupVersionKind(scheme)
			require.NoError(t, err)

			res, statusPatch, err := controller.reconcileStatusPatch(logger, context.TODO(), req)
			var csrStatusPatch *certificatesv1.CertificateSigningRequestStatus
			if statusPatch != nil {
				csrStatusPatch = statusPatch.(CertificateSigningRequestPatch).CertificateSigningRequestPatch()
			}

			assert.Equal(t, tc.expectedResult, res)
			assert.Equal(t, tc.expectedStatusPatch, csrStatusPatch)
			ptr.Deref(tc.validateError, *errormatch.NoError())(t, err)

			allEvents := chanToSlice(fakeRecorder.Events)
			if len(tc.expectedEvents) == 0 {
				assert.Emptyf(t, allEvents, "expected no events to be recorded, but got: %#v", allEvents)
			} else {
				assert.Equal(t, tc.expectedEvents, allEvents)
			}
		})
	}
}

func TestCertificateSigningRequestMatchIssuerType(t *testing.T) {
	t.Parallel()

	type testcase struct {
		name string

		issuerTypes        []v1alpha1.Issuer
		clusterIssuerTypes []v1alpha1.Issuer
		csr                *certificatesv1.CertificateSigningRequest

		expectedIssuerType v1alpha1.Issuer
		expectedIssuerName types.NamespacedName
		expectedError      *errormatch.Matcher
	}

	createCsr := func(signerName string) *certificatesv1.CertificateSigningRequest {
		return &certificatesv1.CertificateSigningRequest{
			Spec: certificatesv1.CertificateSigningRequestSpec{
				SignerName: signerName,
			},
		}
	}

	testcases := []testcase{
		{
			name:               "empty",
			issuerTypes:        nil,
			clusterIssuerTypes: nil,
			csr:                nil,

			expectedIssuerType: nil,
			expectedIssuerName: types.NamespacedName{},
			expectedError:      errormatch.ErrorContains("invalid signer name, should have format <issuer-type-id>/<issuer-id>"),
		},
		{
			name:               "invalid signer name format",
			issuerTypes:        nil,
			clusterIssuerTypes: nil,
			csr:                createCsr("aaaaaa"),

			expectedIssuerType: nil,
			expectedIssuerName: types.NamespacedName{},
			expectedError:      errormatch.ErrorContains("invalid signer name, should have format <issuer-type-id>/<issuer-id>: \"aaaaaa\""),
		},
		{
			name:               "unknown issuer type identifier",
			issuerTypes:        []v1alpha1.Issuer{&api.TestIssuer{}},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.TestClusterIssuer{}},
			csr:                createCsr("aaaaa.testing.cert-manager.io/namespace.name"),

			expectedIssuerType: nil,
			expectedIssuerName: types.NamespacedName{},
			expectedError:      errormatch.ErrorContains("no issuer found for signer name: \"aaaaa.testing.cert-manager.io/namespace.name\""),
		},
		{
			name:               "match issuer",
			issuerTypes:        []v1alpha1.Issuer{&api.TestIssuer{}},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.TestClusterIssuer{}},
			csr:                createCsr("testissuers.testing.cert-manager.io/namespace.name"),

			expectedIssuerType: nil,
			expectedIssuerName: types.NamespacedName{},
			expectedError:      errormatch.ErrorContains("invalid SignerName, \"testissuers.testing.cert-manager.io\" is a namespaced issuer type, namespaced issuers are not supported for Kubernetes CSRs"),
		},
		{
			name:               "match cluster issuer",
			issuerTypes:        []v1alpha1.Issuer{&api.TestIssuer{}},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.TestClusterIssuer{}},
			csr:                createCsr("testclusterissuers.testing.cert-manager.io/name"),

			expectedIssuerType: &api.TestClusterIssuer{},
			expectedIssuerName: types.NamespacedName{Name: "name"},
		},
		{
			name:               "cluster issuer with dot in name",
			issuerTypes:        []v1alpha1.Issuer{&api.TestIssuer{}},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.TestClusterIssuer{}},
			csr:                createCsr("testclusterissuers.testing.cert-manager.io/name.test"),

			expectedIssuerType: &api.TestClusterIssuer{},
			expectedIssuerName: types.NamespacedName{Name: "name.test"},
		},
		{
			name:               "cluster issuer with empty name",
			issuerTypes:        []v1alpha1.Issuer{&api.TestIssuer{}},
			clusterIssuerTypes: []v1alpha1.Issuer{&api.TestClusterIssuer{}},
			csr:                createCsr("testclusterissuers.testing.cert-manager.io/"),

			expectedIssuerType: &api.TestClusterIssuer{},
			expectedIssuerName: types.NamespacedName{Name: ""},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, api.AddToScheme(scheme))

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			crr := &CertificateSigningRequestReconciler{
				RequestController: RequestController{
					IssuerTypes:        tc.issuerTypes,
					ClusterIssuerTypes: tc.clusterIssuerTypes,
				},
			}

			require.NoError(t, crr.setAllIssuerTypesWithGroupVersionKind(scheme))

			issuerType, issuerName, err := crr.matchIssuerType(tc.csr)

			if tc.expectedIssuerType != nil {
				require.NoError(t, kubeutil.SetGroupVersionKind(scheme, tc.expectedIssuerType))
			}

			assert.Equal(t, tc.expectedIssuerType, issuerType)
			assert.Equal(t, tc.expectedIssuerName, issuerName)
			if !ptr.Deref(tc.expectedError, *errormatch.NoError())(t, err) {
				t.Fail()
			}
		})
	}
}
