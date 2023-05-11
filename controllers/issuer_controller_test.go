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
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/tests/cmtime"
	"github.com/cert-manager/issuer-lib/internal/tests/errormatch"
	"github.com/cert-manager/issuer-lib/internal/tests/ptr"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/api"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/testutil"
)

func TestSimpleIssuerReconcilerReconcile(t *testing.T) {
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

	fakeTimeObj := metav1.NewTime(cmtime.FakeTime)

	issuer1 := testutil.SimpleIssuer(
		"issuer-1",
		testutil.SetSimpleIssuerNamespace("ns1"),
	)

	staticChecker := func(err error) signer.Check {
		return func(_ context.Context, _ client.Object) error {
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
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerGeneration(80),
					testutil.SetSimpleIssuerStatusCondition(
						cmapi.IssuerConditionReady,
						cmmeta.ConditionTrue,
						v1alpha1.IssuerConditionReasonChecked,
						"checked",
					),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []cmapi.IssuerCondition{
					{
						Type:               cmapi.IssuerConditionReady,
						Status:             cmmeta.ConditionTrue,
						Reason:             v1alpha1.IssuerConditionReasonChecked,
						Message:            "checked",
						ObservedGeneration: 80,
						LastTransitionTime: &fakeTimeObj,
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
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerGeneration(80),
					testutil.SetSimpleIssuerStatusCondition(
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
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
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerGeneration(80),
					testutil.SetSimpleIssuerStatusCondition(
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
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
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerGeneration(80),
					testutil.SetSimpleIssuerStatusCondition(
						cmapi.IssuerConditionReady,
						cmmeta.ConditionTrue,
						v1alpha1.IssuerConditionReasonChecked,
						"checked",
					),
				),
			},
			eventSourceError: fmt.Errorf("[specific error]"),
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []cmapi.IssuerCondition{
					{
						Type:               cmapi.IssuerConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             v1alpha1.IssuerConditionReasonPending,
						Message:            "Issuer is not ready yet: [specific error]",
						ObservedGeneration: 80,
						LastTransitionTime: &fakeTimeObj,
					},
				},
			},
			// instead of an error, a new reconcile request is triggered by the
			// requeue=true return value
			validateError: errormatch.NoError(),
			expectedResult: reconcile.Result{
				Requeue: true,
			},
			expectedEvents: []string{
				"Warning RetryableError Failed to check issuer, will retry: [specific error]",
			},
		},

		// Re-check if already at Ready for older observed generation
		{
			name:  "recheck-outdated-ready",
			check: staticChecker(nil),
			objects: []client.Object{
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerGeneration(80),
					testutil.SetSimpleIssuerStatusCondition(
						cmapi.IssuerConditionReady,
						cmmeta.ConditionTrue,
						v1alpha1.IssuerConditionReasonChecked,
						"checked",
					),
					testutil.SetSimpleIssuerGeneration(81),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []cmapi.IssuerCondition{
					{
						Type:               cmapi.IssuerConditionReady,
						Status:             cmmeta.ConditionTrue,
						Reason:             v1alpha1.IssuerConditionReasonChecked,
						Message:            "checked",
						LastTransitionTime: &fakeTimeObj,
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
			expectedResult: reconcile.Result{},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []cmapi.IssuerCondition{
					{
						Type:               cmapi.IssuerConditionReady,
						Status:             cmmeta.ConditionUnknown,
						Reason:             v1alpha1.IssuerConditionReasonInitializing,
						Message:            fieldOwner + " has started reconciling this Issuer",
						LastTransitionTime: &fakeTimeObj,
					},
				},
			},
		},

		// Retry if the check function returns an error
		{
			name:  "retry-on-error",
			check: staticChecker(fmt.Errorf("a specific error")),
			objects: []client.Object{
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerStatusCondition(
						cmapi.IssuerConditionReady,
						cmmeta.ConditionUnknown,
						v1alpha1.IssuerConditionReasonInitializing,
						fieldOwner+" has started reconciling this Issuer",
					),
				),
			},
			// instead of an error, a new reconcile request is triggered by the
			// requeue=true return value
			validateError: errormatch.NoError(),
			expectedResult: reconcile.Result{
				Requeue: true,
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []cmapi.IssuerCondition{
					{
						Type:               cmapi.IssuerConditionReady,
						Status:             cmmeta.ConditionFalse,
						Reason:             v1alpha1.IssuerConditionReasonPending,
						Message:            "Issuer is not ready yet: a specific error",
						LastTransitionTime: &fakeTimeObj,
					},
				},
			},
			expectedEvents: []string{
				"Warning RetryableError Failed to check issuer, will retry: a specific error",
			},
		},

		// Retry if the check function returns a dependant resource error
		// > see integration test

		// Success if nothing is wrong
		{
			name:  "success-issuer",
			check: staticChecker(nil),
			objects: []client.Object{
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerStatusCondition(
						cmapi.IssuerConditionReady,
						cmmeta.ConditionUnknown,
						v1alpha1.IssuerConditionReasonInitializing,
						fieldOwner+" has started reconciling this Issuer",
					),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []cmapi.IssuerCondition{
					{
						Type:               cmapi.IssuerConditionReady,
						Status:             cmmeta.ConditionTrue,
						Reason:             v1alpha1.IssuerConditionReasonChecked,
						Message:            "checked",
						LastTransitionTime: &fakeTimeObj,
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
				testutil.SimpleIssuerFrom(issuer1,
					testutil.SetSimpleIssuerGeneration(80),
					testutil.SetSimpleIssuerStatusCondition(
						cmapi.IssuerConditionReady,
						cmmeta.ConditionFalse,
						v1alpha1.IssuerConditionReasonInitializing,
						fieldOwner+" has started reconciling this Issuer",
					),
					testutil.SetSimpleIssuerGeneration(81),
				),
			},
			expectedStatusPatch: &v1alpha1.IssuerStatus{
				Conditions: []cmapi.IssuerCondition{
					{
						Type:               cmapi.IssuerConditionReady,
						Status:             cmmeta.ConditionTrue,
						Reason:             v1alpha1.IssuerConditionReasonChecked,
						Message:            "checked",
						LastTransitionTime: &fakeTimeObj,
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
		tc := tc
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

			var vciBefore api.SimpleIssuer
			err := fakeClient.Get(context.TODO(), req.NamespacedName, &vciBefore)
			require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")

			logger := logrtesting.NewTestLoggerWithOptions(t, logrtesting.Options{LogTimestamp: true, Verbosity: 10})
			fakeRecorder := record.NewFakeRecorder(100)

			controller := IssuerReconciler{
				ForObject:  &api.SimpleIssuer{},
				FieldOwner: fieldOwner,
				EventSource: fakeEventSource{
					err: tc.eventSourceError,
				},
				Client:        fakeClient,
				Check:         tc.check,
				EventRecorder: fakeRecorder,
			}

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
