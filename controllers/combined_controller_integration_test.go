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
	"sync"
	"testing"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/testapi/api"
	"github.com/cert-manager/issuer-lib/internal/testapi/testutil"
	"github.com/cert-manager/issuer-lib/internal/tests/testcontext"
	"github.com/cert-manager/issuer-lib/internal/tests/testresource"
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

	ctx := testcontext.ForTest(t)
	kubeClients := testresource.KubeClients(t, nil)

	checkResult, signResult := make(chan error, 10), make(chan error, 10)
	ctx = setupControllersAPIServerAndClient(t, ctx, kubeClients,
		func(mgr ctrl.Manager) controllerInterface {
			return &CombinedController{
				IssuerTypes:        []v1alpha1.Issuer{&api.TestIssuer{}},
				ClusterIssuerTypes: []v1alpha1.Issuer{&api.TestClusterIssuer{}},
				FieldOwner:         fieldOwner,
				MaxRetryDuration:   time.Minute,
				Check: func(_ context.Context, _ v1alpha1.Issuer) error {
					select {
					case err := <-checkResult:
						return err
					case <-ctx.Done():
						return ctx.Err()
					}
				},
				Sign: func(_ context.Context, _ signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, signer.ExtraConditions, error) {
					select {
					case err := <-signResult:
						return signer.PEMBundle{}, signer.ExtraConditions{}, err
					case <-ctx.Done():
						return signer.PEMBundle{}, signer.ExtraConditions{}, ctx.Err()
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
				Message: "Not ready yet: [error message]",
			},
			certificateReadyCondition: &cmapi.CertificateRequestCondition{
				Type:    cmapi.CertificateRequestConditionReady,
				Status:  cmmeta.ConditionFalse,
				Reason:  cmapi.CertificateRequestReasonPending,
				Message: "Waiting for issuer to become ready. Current issuer ready condition is \"Pending\": Not ready yet: [error message].",
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
				Message: "Failed permanently: [error message]",
			},
			certificateReadyCondition: &cmapi.CertificateRequestCondition{
				Type:    cmapi.CertificateRequestConditionReady,
				Status:  cmmeta.ConditionFalse,
				Reason:  cmapi.CertificateRequestReasonPending,
				Message: "Waiting for issuer to become ready. Current issuer ready condition is \"Failed\": Failed permanently: [error message].",
			},
			checkAutoRecovery: false,
		},
	}

	// run tests sequentially
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Creating a namespace")
			namespace, cleanup := kubeClients.SetupNamespace(t, ctx)
			defer cleanup()

			issuer := testutil.TestIssuer(
				"issuer-1",
				testutil.SetTestIssuerNamespace(namespace),
				testutil.SetTestIssuerGeneration(70),
				testutil.SetTestIssuerStatusCondition(
					clock.RealClock{},
					cmapi.IssuerConditionReady,
					cmmeta.ConditionTrue,
					v1alpha1.IssuerConditionReasonChecked,
					"Succeeded checking the issuer",
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
			t.Log("Creating the TestIssuer")
			require.NoError(t, kubeClients.Client.Create(ctx, issuer))
			checkResult <- error(nil)
			t.Log("Waiting for the TestIssuer to be Ready")
			err := checkComplete(func(obj runtime.Object) error {
				readyCondition := conditions.GetIssuerStatusCondition(obj.(*api.TestIssuer).Status.Conditions, cmapi.IssuerConditionReady)

				if (readyCondition == nil) ||
					(readyCondition.ObservedGeneration != issuer.Generation) ||
					(readyCondition.Status != cmmeta.ConditionTrue) ||
					(readyCondition.Reason != v1alpha1.IssuerConditionReasonChecked) ||
					(readyCondition.Message != "Succeeded checking the issuer") {
					return fmt.Errorf("incorrect ready condition: %v", readyCondition)
				}

				return nil
			}, watch.Added, watch.Modified)
			require.NoError(t, err)

			createApprovedCR(t, ctx, kubeClients.Client, cr)

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
					(readyCondition.Message != "Waiting for issuer to become ready. Current issuer ready condition is outdated.") {
					return fmt.Errorf("incorrect ready condition: %v", readyCondition)
				}

				return nil
			}, watch.Added, watch.Modified)
			require.NoError(t, err)

			t.Log("Waiting for Issuer to have a Pending IssuerFailedWillRetry condition")
			err = checkIssuerComplete(func(obj runtime.Object) error {
				readyCondition := conditions.GetIssuerStatusCondition(obj.(*api.TestIssuer).Status.Conditions, cmapi.IssuerConditionReady)

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
					readyCondition := conditions.GetIssuerStatusCondition(obj.(*api.TestIssuer).Status.Conditions, cmapi.IssuerConditionReady)

					if (readyCondition == nil) ||
						(readyCondition.ObservedGeneration != issuer.Generation) ||
						(readyCondition.Status != cmmeta.ConditionTrue) ||
						(readyCondition.Reason != v1alpha1.IssuerConditionReasonChecked) ||
						(readyCondition.Message != "Succeeded checking the issuer") {
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
						(readyCondition.Message != "Succeeded signing the CertificateRequest") {
						return fmt.Errorf("incorrect ready condition: %v", readyCondition)
					}

					return nil
				}, watch.Added, watch.Modified)
				require.NoError(t, err)
			}
		})
	}
}

func TestCombinedControllerTiming(t *testing.T) { //nolint:tparallel
	t.Parallel()

	t.Log(
		"Tests to show that the CertificateRequest controller and Issuer controller call the Check and Sign functions at the correct times",
	)

	fieldOwner := "failed-certificate-request-should-retrigger-issuer"

	ctx := testcontext.ForTest(t)
	kubeClients := testresource.KubeClients(t, nil)

	type simulatedCheckResult struct {
		err error
	}
	type simulatedSignResult struct {
		cert []byte
		err  error
	}

	type simulatedResult struct {
		*simulatedCheckResult
		*simulatedSignResult
		expectedSinceLastResult time.Duration
	}

	type testcase struct {
		name             string
		maxRetryDuration time.Duration
		results          []simulatedResult
	}

	testcases := []testcase{
		{
			name:             "single-error-for-issuer-and-certificate-request",
			maxRetryDuration: 1 * time.Hour,
			results: []simulatedResult{
				{
					simulatedCheckResult:    &simulatedCheckResult{err: fmt.Errorf("[error message]")},
					expectedSinceLastResult: 0,
				},
				{
					simulatedCheckResult:    &simulatedCheckResult{err: nil},
					expectedSinceLastResult: 200 * time.Millisecond,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: nil, err: fmt.Errorf("[error message]")},
					expectedSinceLastResult: 0,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: []byte("cert"), err: nil},
					expectedSinceLastResult: 200 * time.Millisecond,
				},
			},
		},
		{
			name:             "double-error-for-issuer-and-certificate-request",
			maxRetryDuration: 1 * time.Hour,
			results: []simulatedResult{
				{
					simulatedCheckResult:    &simulatedCheckResult{err: fmt.Errorf("[error message]")},
					expectedSinceLastResult: 0,
				},
				{
					simulatedCheckResult:    &simulatedCheckResult{err: fmt.Errorf("[error message]")},
					expectedSinceLastResult: 200 * time.Millisecond,
				},
				{
					simulatedCheckResult:    &simulatedCheckResult{err: nil},
					expectedSinceLastResult: 400 * time.Millisecond,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: nil, err: fmt.Errorf("[error message]")},
					expectedSinceLastResult: 0,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: nil, err: fmt.Errorf("[error message]")},
					expectedSinceLastResult: 200 * time.Millisecond,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: []byte("cert"), err: nil},
					expectedSinceLastResult: 400 * time.Millisecond,
				},
			},
		},
		{
			name:             "single-error-for-issuer-and-certificate-request-reaching-max-retry-duration",
			maxRetryDuration: 300 * time.Millisecond, // should cause temporary CertificateRequest errors to fail permanently
			results: []simulatedResult{
				{
					simulatedCheckResult:    &simulatedCheckResult{err: fmt.Errorf("[error message]")},
					expectedSinceLastResult: 0,
				},
				{
					simulatedCheckResult:    &simulatedCheckResult{err: nil},
					expectedSinceLastResult: 200 * time.Millisecond,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: nil, err: fmt.Errorf("[error message]")},
					expectedSinceLastResult: 0,
				},
			},
		},
		{
			name:             "single-pending-error-for-issuer-and-certificate-request-reaching-max-retry-duration",
			maxRetryDuration: 300 * time.Millisecond, // should cause temporary CertificateRequest errors to fail permanently
			results: []simulatedResult{
				{
					simulatedCheckResult:    &simulatedCheckResult{err: fmt.Errorf("[error message]")},
					expectedSinceLastResult: 0,
				},
				{
					simulatedCheckResult:    &simulatedCheckResult{err: nil},
					expectedSinceLastResult: 200 * time.Millisecond,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: nil, err: signer.PendingError{Err: fmt.Errorf("[error message]")}},
					expectedSinceLastResult: 0,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: []byte("ok"), err: nil},
					expectedSinceLastResult: 200 * time.Millisecond,
				},
			},
		},
		{
			name:             "fail-issuer-permanently",
			maxRetryDuration: 1 * time.Hour,
			results: []simulatedResult{
				{
					simulatedCheckResult:    &simulatedCheckResult{err: signer.PermanentError{Err: fmt.Errorf("[error message]")}},
					expectedSinceLastResult: 0,
				},
			},
		},
		{
			name:             "trigger-issuer-error-then-recover",
			maxRetryDuration: 1 * time.Hour,
			results: []simulatedResult{
				{
					simulatedCheckResult:    &simulatedCheckResult{err: nil},
					expectedSinceLastResult: 0,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: nil, err: signer.IssuerError{Err: fmt.Errorf("[error message]")}},
					expectedSinceLastResult: 0,
				},
				{
					simulatedCheckResult:    &simulatedCheckResult{err: nil},
					expectedSinceLastResult: 200 * time.Millisecond,
				},
				{
					simulatedSignResult:     &simulatedSignResult{cert: []byte("ok"), err: nil},
					expectedSinceLastResult: 0,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			resultsMutex := sync.Mutex{}
			resultsIndex := 0
			results := tc.results
			durations := make([]time.Time, len(results))
			errorCh := make(chan error)
			done := make(chan struct{})

			ctx := setupControllersAPIServerAndClient(t, ctx, kubeClients,
				func(mgr ctrl.Manager) controllerInterface {
					return &CombinedController{
						IssuerTypes:        []v1alpha1.Issuer{&api.TestIssuer{}},
						ClusterIssuerTypes: []v1alpha1.Issuer{&api.TestClusterIssuer{}},
						FieldOwner:         fieldOwner,
						MaxRetryDuration:   tc.maxRetryDuration,
						Check: func(_ context.Context, _ v1alpha1.Issuer) error {
							resultsMutex.Lock()
							defer resultsMutex.Unlock()
							defer func() { resultsIndex++ }()

							if resultsIndex >= len(results)-1 {
								if resultsIndex > len(results)-1 {
									errorCh <- fmt.Errorf("too many calls to Check")
									return nil
								}
								defer close(done)
							}
							durations[resultsIndex] = time.Now()
							if results[resultsIndex].simulatedCheckResult == nil {
								errorCh <- fmt.Errorf("unexpected call to Check")
								return nil
							}
							return results[resultsIndex].simulatedCheckResult.err
						},
						Sign: func(_ context.Context, _ signer.CertificateRequestObject, _ v1alpha1.Issuer) (signer.PEMBundle, signer.ExtraConditions, error) {
							resultsMutex.Lock()
							defer resultsMutex.Unlock()
							defer func() { resultsIndex++ }()

							if resultsIndex >= len(results)-1 {
								if resultsIndex > len(results)-1 {
									errorCh <- fmt.Errorf("too many calls to Sign")
									return signer.PEMBundle{}, signer.ExtraConditions{}, nil
								}
								defer close(done)
							}
							durations[resultsIndex] = time.Now()
							if results[resultsIndex].simulatedSignResult == nil {
								errorCh <- fmt.Errorf("unexpected call to Sign")
								return signer.PEMBundle{}, signer.ExtraConditions{}, nil
							}
							result := results[resultsIndex].simulatedSignResult
							return signer.PEMBundle{
								ChainPEM: result.cert,
							}, signer.ExtraConditions{}, result.err
						},
						EventRecorder: record.NewFakeRecorder(100),

						PreSetupWithManager: func(ctx context.Context, gvk schema.GroupVersionKind, mgr ctrl.Manager, b *builder.Builder) error {
							b.WithOptions(controller.Options{
								RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](200*time.Millisecond, 5*time.Second),
							})
							return nil
						},
					}
				},
			)

			t.Logf("Creating a namespace")
			namespace, cleanup := kubeClients.SetupNamespace(t, ctx)
			defer cleanup()

			issuer := testutil.TestIssuer(
				"issuer-1",
				testutil.SetTestIssuerNamespace(namespace),
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

			require.NoError(t, kubeClients.Client.Create(ctx, issuer))
			createApprovedCR(t, ctx, kubeClients.Client, cr)

			<-done
			time.Sleep(1 * time.Second)
			select {
			case err := <-errorCh:
				assert.NoError(t, err)
			default:
			}

			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				err := kubeClients.Client.Get(ctx, client.ObjectKeyFromObject(cr), cr)
				if err != nil {
					return err
				}
				return kubeClients.Client.Delete(ctx, cr)
			}))
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				err := kubeClients.Client.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)
				if err != nil {
					return err
				}
				return kubeClients.Client.Delete(ctx, issuer)
			}))

			for i := 1; i < len(results); i++ {
				measuredDuration := durations[i].Sub(durations[i-1])
				expectedDuration := results[i].expectedSinceLastResult

				require.True(t, expectedDuration-150*time.Millisecond < measuredDuration, "result %d: expected %v, got %v", i, expectedDuration, measuredDuration)
				require.True(t, expectedDuration+150*time.Millisecond > measuredDuration, "result %d: expected %v, got %v", i, expectedDuration, measuredDuration)
			}
		})
	}
}
