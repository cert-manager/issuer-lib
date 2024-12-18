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
	"fmt"
	"math/rand"
	"testing"
	"time"

	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/testapi/api"
	"github.com/cert-manager/issuer-lib/internal/testapi/testutil"
	"github.com/cert-manager/issuer-lib/internal/tests/errormatch"
)

// We are using a random time generator to generate random times for the
// fakeClock. This will result in different times for each test run and
// should make sure we don't incorrectly rely on `time.Now()` in the code.
// WARNING: This approach does not guarantee that incorrect use of `time.Now()`
// is always detected, but after a few test runs it should be very unlikely.
func randomTime() time.Time {
	minTime := time.Date(1970, 1, 0, 0, 0, 0, 0, time.UTC).Unix()
	maxTime := time.Date(2070, 1, 0, 0, 0, 0, 0, time.UTC).Unix()
	delta := maxTime - minTime

	sec := rand.Int63n(delta) + minTime // #nosec: G404 -- The random time does not have to be secure.
	return time.Unix(sec, 0)
}

func TestTestIssuerReconcilerReconcile(t *testing.T) {
	t.Parallel()

	fieldOwner := "test-simple-issuer-reconciler-reconcile"

	type testCase struct {
		name                string
		check               signer.Check
		objects             []client.Object
		eventSourceError    error
		validateError       *errormatch.Matcher
		expectedResult      reconcile.Result
		expectedStatusPatch *v1alpha1.IssuerStatus
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
	)

	staticChecker := func(err error) signer.Check {
		return func(_ context.Context, _ v1alpha1.Issuer) error {
			return err
		}
	}

	tests := []testCase{
		// Ignore if issuer not found
		{
			name:                "ignore-issuer-not-found",
			check:               staticChecker(nil),
			objects:             []client.Object{},
			expectedStatusPatch: nil,
		},

		// Update status, even if already at Ready for observed generation
		{
			name:  "trigger-when-ready",
			check: staticChecker(nil),
			objects: []client.Object{
				testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
					testutil.SetTestIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionTrue,
						v1alpha1.IssuerConditionReasonChecked,
						"Succeeded checking the issuer",
					),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []metav1.Condition{
					{
						Type:               v1alpha1.IssuerConditionTypeReady,
						Status:             metav1.ConditionTrue,
						Reason:             v1alpha1.IssuerConditionReasonChecked,
						Message:            "Succeeded checking the issuer",
						ObservedGeneration: 80,
						LastTransitionTime: fakeTimeObj1, // since the status is not updated, the LastTransitionTime is not updated either
					},
				},
			},
			expectedEvents: []string{
				"Normal Checked Succeeded checking the issuer",
			},
		},

		// Ignore if already at Failed for observed generation
		{
			name:  "ignore-failed",
			check: staticChecker(nil),
			objects: []client.Object{
				testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
					testutil.SetTestIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionFalse,
						v1alpha1.IssuerConditionReasonFailed,
						"[error message]",
					),
				),
			},
			expectedStatusPatch: nil,
		},

		// Ignore reported error if not ready
		{
			name:  "failed-ignore-reported-error",
			check: staticChecker(nil),
			objects: []client.Object{
				testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
					testutil.SetTestIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionFalse,
						v1alpha1.IssuerConditionReasonFailed,
						"[error message]",
					),
				),
			},
			eventSourceError:    fmt.Errorf("[specific error]"),
			expectedStatusPatch: nil,
		},

		// Set error if the CertificateRequest controller reported error
		{
			name:  "ready-reported-error",
			check: staticChecker(nil),
			objects: []client.Object{
				testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
					testutil.SetTestIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionTrue,
						v1alpha1.IssuerConditionReasonChecked,
						"Succeeded checking the issuer",
					),
				),
			},
			eventSourceError: fmt.Errorf("[specific error]"),
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []metav1.Condition{
					{
						Type:               v1alpha1.IssuerConditionTypeReady,
						Status:             metav1.ConditionFalse,
						Reason:             v1alpha1.IssuerConditionReasonPending,
						Message:            "Not ready yet: [specific error]",
						ObservedGeneration: 80,
						LastTransitionTime: fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("[specific error]"),
			expectedEvents: []string{
				"Warning RetryableError Not ready yet: [specific error]",
			},
		},

		// Re-check if already at Ready for older observed generation
		{
			name:  "recheck-outdated-ready",
			check: staticChecker(nil),
			objects: []client.Object{
				testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
					testutil.SetTestIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionTrue,
						v1alpha1.IssuerConditionReasonChecked,
						"Succeeded checking the issuer",
					),
					testutil.SetTestIssuerGeneration(81),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []metav1.Condition{
					{
						Type:               v1alpha1.IssuerConditionTypeReady,
						Status:             metav1.ConditionTrue,
						Reason:             v1alpha1.IssuerConditionReasonChecked,
						Message:            "Succeeded checking the issuer",
						LastTransitionTime: fakeTimeObj1, // since the status is not updated, the LastTransitionTime is not updated either
						ObservedGeneration: 81,
					},
				},
			},
			expectedEvents: []string{
				"Normal Checked Succeeded checking the issuer",
			},
		},

		// Initialize the Issuer Ready condition if it is missing
		{
			name: "initialize-ready-condition",
			objects: []client.Object{
				issuer1,
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []metav1.Condition{
					{
						Type:               v1alpha1.IssuerConditionTypeReady,
						Status:             metav1.ConditionUnknown,
						Reason:             v1alpha1.IssuerConditionReasonInitializing,
						Message:            fieldOwner + " has started reconciling this Issuer",
						LastTransitionTime: fakeTimeObj2,
					},
				},
			},
		},

		// Retry if the check function returns an error
		{
			name:  "retry-on-error",
			check: staticChecker(fmt.Errorf("[specific error]")),
			objects: []client.Object{
				testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionUnknown,
						v1alpha1.IssuerConditionReasonInitializing,
						fieldOwner+" has started reconciling this Issuer",
					),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []metav1.Condition{
					{
						Type:               v1alpha1.IssuerConditionTypeReady,
						Status:             metav1.ConditionFalse,
						Reason:             v1alpha1.IssuerConditionReasonPending,
						Message:            "Not ready yet: [specific error]",
						LastTransitionTime: fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("[specific error]"),
			expectedEvents: []string{
				"Warning RetryableError Not ready yet: [specific error]",
			},
		},

		// Don't retry if the check function returns a permanent error
		{
			name:  "dont-retry-on-permanent-error",
			check: staticChecker(signer.PermanentError{Err: fmt.Errorf("[specific error]")}),
			objects: []client.Object{
				testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionUnknown,
						v1alpha1.IssuerConditionReasonInitializing,
						fieldOwner+" has started reconciling this Issuer",
					),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []metav1.Condition{
					{
						Type:               v1alpha1.IssuerConditionTypeReady,
						Status:             metav1.ConditionFalse,
						Reason:             v1alpha1.IssuerConditionReasonFailed,
						Message:            "Failed permanently: [specific error]",
						LastTransitionTime: fakeTimeObj2,
					},
				},
			},
			validateError: errormatch.ErrorContains("terminal error: [specific error]"),
			expectedEvents: []string{
				"Warning PermanentError Failed permanently: [specific error]",
			},
		},

		// Retry if the check function returns a dependant resource error
		// > see integration test

		// Success if nothing is wrong
		{
			name:  "success-issuer",
			check: staticChecker(nil),
			objects: []client.Object{
				testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionUnknown,
						v1alpha1.IssuerConditionReasonInitializing,
						fieldOwner+" has started reconciling this Issuer",
					),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []metav1.Condition{
					{
						Type:               v1alpha1.IssuerConditionTypeReady,
						Status:             metav1.ConditionTrue,
						Reason:             v1alpha1.IssuerConditionReasonChecked,
						Message:            "Succeeded checking the issuer",
						LastTransitionTime: fakeTimeObj2,
					},
				},
			},
			expectedEvents: []string{
				"Normal Checked Succeeded checking the issuer",
			},
		},

		// Set the Ready condition to Ready if the check function returned a permanent error on a previous version
		{
			name:  "success-recover",
			check: staticChecker(nil),
			objects: []client.Object{
				testutil.TestIssuerFrom(issuer1,
					testutil.SetTestIssuerGeneration(80),
					testutil.SetTestIssuerStatusCondition(
						fakeClock1,
						v1alpha1.IssuerConditionTypeReady,
						metav1.ConditionFalse,
						v1alpha1.IssuerConditionReasonInitializing,
						fieldOwner+" has started reconciling this Issuer",
					),
					testutil.SetTestIssuerGeneration(81),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []metav1.Condition{
					{
						Type:               v1alpha1.IssuerConditionTypeReady,
						Status:             metav1.ConditionTrue,
						Reason:             v1alpha1.IssuerConditionReasonChecked,
						Message:            "Succeeded checking the issuer",
						LastTransitionTime: fakeTimeObj2,
						ObservedGeneration: 81,
					},
				},
			},
			expectedEvents: []string{
				"Normal Checked Succeeded checking the issuer",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scheme := runtime.NewScheme()
			require.NoError(t, api.AddToScheme(scheme))
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.objects...).
				Build()

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      issuer1.Name,
					Namespace: issuer1.Namespace,
				},
			}

			var vciBefore api.TestIssuer
			err := fakeClient.Get(context.TODO(), req.NamespacedName, &vciBefore)
			require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")

			logger := logrtesting.NewTestLoggerWithOptions(t, logrtesting.Options{LogTimestamp: true, Verbosity: 10})
			fakeRecorder := record.NewFakeRecorder(100)

			controller := IssuerReconciler{
				ForObject:  &api.TestIssuer{},
				FieldOwner: fieldOwner,
				EventSource: fakeEventSource{
					err: tc.eventSourceError,
				},
				Client:        fakeClient,
				Check:         tc.check,
				EventRecorder: fakeRecorder,
				Clock:         fakeClock2,
			}

			res, issuerStatusPatch, reconcileErr := controller.reconcileStatusPatch(logger, context.TODO(), req)

			assert.Equal(t, tc.expectedResult, res)
			assert.Equal(t, tc.expectedStatusPatch, issuerStatusPatch)
			ptr.Deref(tc.validateError, *errormatch.NoError())(t, reconcileErr)

			allEvents := chanToSlice(fakeRecorder.Events)
			if len(tc.expectedEvents) == 0 {
				assert.Emptyf(t, allEvents, "expected no events to be recorded, but got: %#v", allEvents)
			} else {
				assert.Equal(t, tc.expectedEvents, allEvents)
			}
		})
	}
}

type fakeEventSource struct {
	err error
}

func (fakeEventSource) AddConsumer(gvk schema.GroupVersionKind) source.Source {
	panic("not implemented")
}
func (fakeEventSource) ReportError(gvk schema.GroupVersionKind, namespacedName types.NamespacedName, err error) error {
	panic("not implemented")
}

func (fes fakeEventSource) HasReportedError(gvk schema.GroupVersionKind, namespacedName types.NamespacedName) error {
	return fes.err
}
