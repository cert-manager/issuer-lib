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
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/tests/testcontext"
	"github.com/cert-manager/issuer-lib/internal/tests/testresource"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/api"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/testutil"
)

// TestCombinedControllerIntegration runs the
// CombinedController against a real Kubernetes API server.
func TestCombinedControllerTemporaryFailedCertificateRequestRetrigger(t *testing.T) { //nolint:tparallel
	t.Parallel()

	t.Log(
		"Tests to show that the CertificateRequest controller handles IssuerErrors from the Sign function correctly",
		"i.e. that it updates the CertificateRequest status to Ready=false with a Pending reason",
		"and that it updates the Issuer status to Ready=false with a Pending reason or Ready=false with a Failed reason if the IssuerError wraps a PermanentError",
		"Additionally, it tests that the Issuer Controller is able to recover from a temporary IssuerError",
	)

	fieldOwner := "failed-certificate-request-should-retrigger-issuer"

	ctx := testresource.EnsureTestDependencies(t, testcontext.ForTest(t), testresource.UnitTest)
	kubeClients := testresource.KubeClients(t, ctx)

	checkResult, signResult := make(chan error, 10), make(chan error, 10)
	ctx = setupControllersAPIServerAndClient(t, ctx, kubeClients,
		func(mgr ctrl.Manager) controllerInterface {
			return &CombinedController{
				IssuerTypes:        []v1alpha1.Issuer{&api.SimpleIssuer{}},
				ClusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleClusterIssuer{}},
				FieldOwner:         fieldOwner,
				MaxRetryDuration:   time.Minute,
				Check: func(_ context.Context, _ client.Object) error {
					select {
					case err := <-checkResult:
						return err
					case <-ctx.Done():
						return ctx.Err()
					}
				},
				Sign: func(_ context.Context, _ *cmapi.CertificateRequest, _ client.Object) ([]byte, error) {
					select {
					case err := <-signResult:
						return nil, err
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				},
				EventRecorder: record.NewFakeRecorder(100),
			}
		},
	)

	type testcase struct {
		name                      string
		issuerError               error
		issuerReadyCondition      *cmapi.IssuerCondition
		certificateReadyCondition *cmapi.CertificateRequestCondition
		checkAutoRecovery         bool
	}

	testcases := []testcase{
		{
			name:        "test-normal-error",
			issuerError: fmt.Errorf("[error message]"),
			issuerReadyCondition: &cmapi.IssuerCondition{
				Type:    cmapi.IssuerConditionReady,
				Status:  cmmeta.ConditionFalse,
				Reason:  v1alpha1.IssuerConditionReasonPending,
				Message: "Issuer is not ready yet: [error message]",
			},
			certificateReadyCondition: &cmapi.CertificateRequestCondition{
				Type:    cmapi.CertificateRequestConditionReady,
				Status:  cmmeta.ConditionFalse,
				Reason:  cmapi.CertificateRequestReasonPending,
				Message: "Issuer is not Ready yet. Current ready condition is \"Pending\": Issuer is not ready yet: [error message]. Waiting for it to become ready.",
			},
			checkAutoRecovery: true,
		},
		{
			name:        "test-permanent-error",
			issuerError: signer.PermanentError{Err: fmt.Errorf("[error message]")},
			issuerReadyCondition: &cmapi.IssuerCondition{
				Type:    cmapi.IssuerConditionReady,
				Status:  cmmeta.ConditionFalse,
				Reason:  v1alpha1.IssuerConditionReasonFailed,
				Message: "Issuer has failed permanently: [error message]",
			},
			certificateReadyCondition: &cmapi.CertificateRequestCondition{
				Type:    cmapi.CertificateRequestConditionReady,
				Status:  cmmeta.ConditionFalse,
				Reason:  cmapi.CertificateRequestReasonPending,
				Message: "Issuer is not Ready yet. Current ready condition is \"Failed\": Issuer has failed permanently: [error message]. Waiting for it to become ready.",
			},
			checkAutoRecovery: false,
		},
	}

	// run tests sequentially
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Creating a namespace")
			namespace, cleanup := kubeClients.SetupNamespace(t, ctx)
			defer cleanup()

			issuer := testutil.SimpleIssuer(
				"issuer-1",
				testutil.SetSimpleIssuerNamespace(namespace),
				testutil.SetSimpleIssuerGeneration(70),
				testutil.SetSimpleIssuerStatusCondition(
					clock.RealClock{},
					cmapi.IssuerConditionReady,
					cmmeta.ConditionTrue,
					v1alpha1.IssuerConditionReasonChecked,
					"checked",
				),
			)

			cr := cmgen.CertificateRequest(
				"certificate-request-1",
				cmgen.SetCertificateRequestNamespace(namespace),
				cmgen.SetCertificateRequestCSR([]byte("doo")),
				cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  issuer.Name,
					Kind:  issuer.Kind,
					Group: api.SchemeGroupVersion.Group,
				}),
			)

			checkComplete := kubeClients.StartObjectWatch(t, ctx, issuer)
			t.Log("Creating the SimpleIssuer")
			require.NoError(t, kubeClients.Client.Create(ctx, issuer))
			checkResult <- error(nil)
			t.Log("Waiting for the SimpleIssuer to be Ready")
			err := checkComplete(func(obj runtime.Object) error {
				readyCondition := conditions.GetIssuerStatusCondition(obj.(*api.SimpleIssuer).Status.Conditions, cmapi.IssuerConditionReady)

				if (readyCondition == nil) ||
					(readyCondition.ObservedGeneration != issuer.Generation) ||
					(readyCondition.Status != cmmeta.ConditionTrue) ||
					(readyCondition.Reason != v1alpha1.IssuerConditionReasonChecked) ||
					(readyCondition.Message != "checked") {
					return fmt.Errorf("incorrect ready condition: %v", readyCondition)
				}

				return nil
			}, watch.Added, watch.Modified)
			require.NoError(t, err)

			createApprovedCR(t, ctx, kubeClients.Client, clock.RealClock{}, cr)

			checkCr1Complete := kubeClients.StartObjectWatch(t, ctx, cr)
			checkCr2Complete := kubeClients.StartObjectWatch(t, ctx, cr)
			checkIssuerComplete := kubeClients.StartObjectWatch(t, ctx, issuer)

			signResult <- error(signer.IssuerError{Err: tc.issuerError})

			t.Log("Waiting for CertificateRequest to have a Pending IssuerOutdated condition")
			err = checkCr1Complete(func(obj runtime.Object) error {
				readyCondition := cmutil.GetCertificateRequestCondition(obj.(*cmapi.CertificateRequest), cmapi.CertificateRequestConditionReady)

				if (readyCondition == nil) ||
					(readyCondition.Status != cmmeta.ConditionFalse) ||
					(readyCondition.Reason != cmapi.CertificateRequestReasonPending) ||
					(readyCondition.Message != "Issuer is not Ready yet. Current ready condition is outdated. Waiting for it to become ready.") {
					return fmt.Errorf("incorrect ready condition: %v", readyCondition)
				}

				return nil
			}, watch.Added, watch.Modified)
			require.NoError(t, err)

			t.Log("Waiting for Issuer to have a Pending IssuerFailedWillRetry condition")
			err = checkIssuerComplete(func(obj runtime.Object) error {
				readyCondition := conditions.GetIssuerStatusCondition(obj.(*api.SimpleIssuer).Status.Conditions, cmapi.IssuerConditionReady)

				if (readyCondition == nil) ||
					(readyCondition.ObservedGeneration != issuer.Generation) ||
					(readyCondition.Status != tc.issuerReadyCondition.Status) ||
					(readyCondition.Reason != tc.issuerReadyCondition.Reason) ||
					(readyCondition.Message != tc.issuerReadyCondition.Message) {
					return fmt.Errorf("incorrect ready condition: %v", readyCondition)
				}

				return nil
			}, watch.Added, watch.Modified)
			require.NoError(t, err)

			t.Log("Waiting for CertificateRequest to have a Pending IssuerNotReady condition")
			err = checkCr2Complete(func(obj runtime.Object) error {
				readyCondition := cmutil.GetCertificateRequestCondition(obj.(*cmapi.CertificateRequest), cmapi.CertificateRequestConditionReady)

				if (readyCondition == nil) ||
					(readyCondition.Status != tc.certificateReadyCondition.Status) ||
					(readyCondition.Reason != tc.certificateReadyCondition.Reason) ||
					(readyCondition.Message != tc.certificateReadyCondition.Message) {
					return fmt.Errorf("incorrect ready condition: %v", readyCondition)
				}

				return nil
			}, watch.Added, watch.Modified)
			require.NoError(t, err)

			if tc.checkAutoRecovery {
				t.Log("Waiting for Issuer to have a Ready Checked condition")
				checkComplete = kubeClients.StartObjectWatch(t, ctx, issuer)
				checkResult <- error(nil)
				err = checkComplete(func(obj runtime.Object) error {
					readyCondition := conditions.GetIssuerStatusCondition(obj.(*api.SimpleIssuer).Status.Conditions, cmapi.IssuerConditionReady)

					if (readyCondition == nil) ||
						(readyCondition.ObservedGeneration != issuer.Generation) ||
						(readyCondition.Status != cmmeta.ConditionTrue) ||
						(readyCondition.Reason != v1alpha1.IssuerConditionReasonChecked) ||
						(readyCondition.Message != "checked") {
						return fmt.Errorf("incorrect ready condition: %v", readyCondition)
					}

					return nil
				}, watch.Added, watch.Modified)
				require.NoError(t, err)

				t.Log("Waiting for CertificateRequest to have a Ready Issued condition")
				checkComplete = kubeClients.StartObjectWatch(t, ctx, cr)
				signResult <- error(nil)
				err = checkComplete(func(obj runtime.Object) error {
					readyCondition := cmutil.GetCertificateRequestCondition(obj.(*cmapi.CertificateRequest), cmapi.CertificateRequestConditionReady)

					if (readyCondition == nil) ||
						(readyCondition.Status != cmmeta.ConditionTrue) ||
						(readyCondition.Reason != cmapi.CertificateRequestReasonIssued) ||
						(readyCondition.Message != "issued") {
						return fmt.Errorf("incorrect ready condition: %v", readyCondition)
					}

					return nil
				}, watch.Added, watch.Modified)
				require.NoError(t, err)
			}
		})
	}
}
