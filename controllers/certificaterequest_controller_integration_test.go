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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/kubeutil"
	"github.com/cert-manager/issuer-lib/internal/ssaclient"
	"github.com/cert-manager/issuer-lib/internal/tests/testcontext"
	"github.com/cert-manager/issuer-lib/internal/tests/testresource"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/api"
)

func extractIdFromNamespace(t *testing.T, namespace string) int {
	t.Helper()

	parts := strings.Split(namespace, "-")
	testId, err := strconv.Atoi(parts[1])
	require.NoError(t, err)
	return testId
}

func addIdToNamespace(t *testing.T, testId int, namespace string) string {
	t.Helper()

	return fmt.Sprintf("%s-%d", strings.ReplaceAll(namespace, "-", ""), testId)
}

// TestCertificateRequestControllerIntegrationIssuerInitiallyNotFoundAndNotReady runs the
// CertificateRequestController against a real Kubernetes API server.
func TestCertificateRequestControllerIntegrationIssuerInitiallyNotFoundAndNotReady(t *testing.T) {
	t.Parallel()

	fieldOwner := "issuer-or-clusterissuer-initially-not-found-and-not-ready"

	ctx := testresource.EnsureTestDependencies(t, testcontext.ForTest(t), testresource.UnitTest)
	kubeClients := testresource.KubeClients(t, ctx)

	counters := []uint64{}
	ctx = setupControllersAPIServerAndClient(t, ctx, kubeClients,
		func(mgr ctrl.Manager) controllerInterface {
			return &CertificateRequestReconciler{
				IssuerTypes:        []v1alpha1.Issuer{&api.SimpleIssuer{}},
				ClusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleClusterIssuer{}},
				FieldOwner:         fieldOwner,
				MaxRetryDuration:   time.Minute,
				EventSource:        kubeutil.NewEventStore(),
				Client:             mgr.GetClient(),
				Sign: func(_ context.Context, cr *cmapi.CertificateRequest, _ client.Object) ([]byte, error) {
					atomic.AddUint64(&counters[extractIdFromNamespace(t, cr.Namespace)], 1)
					return []byte("ok"), nil
				},
				EventRecorder: record.NewFakeRecorder(100),
			}
		},
	)

	t.Log(
		"Tests to show that the controller watches Issuer and ClusterIssuer resources ",
		"and that it re-reconciles all related CertificateRequest resources",
		"and that it waits for the issuer to become ready",
	)
	type testCase struct {
		name       string
		issuerType string
	}

	tests := []testCase{
		{
			name:       "issuer",
			issuerType: "SimpleIssuer",
		},
		{
			name:       "clusterissuer",
			issuerType: "SimpleClusterIssuer",
		},
	}

	for testId, tc := range tests {
		counters = append(counters, 0)
		tc := tc
		testId := testId
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			crName := types.NamespacedName{
				Name:      "cr1",
				Namespace: addIdToNamespace(t, testId, tc.name),
			}

			t.Logf("Creating a namespace: %s", crName.Namespace)
			createNS(t, ctx, kubeClients.Client, crName.Namespace)

			cr := cmgen.CertificateRequest(
				crName.Name,
				cmgen.SetCertificateRequestNamespace(crName.Namespace),
				cmgen.SetCertificateRequestCSR([]byte("doo")),
				cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "issuer-1",
					Kind:  tc.issuerType,
					Group: api.SchemeGroupVersion.Group,
				}),
			)

			checkComplete := kubeClients.StartObjectWatch(t, ctx, cr)
			t.Log("Creating & approving the CertificateRequest")
			createApprovedCR(t, ctx, kubeClients.Client, cr)
			t.Log("Waiting for controller to mark the CertificateRequest as IssuerNotFound")
			err := checkComplete(func(obj runtime.Object) error {
				readyCondition := cmutil.GetCertificateRequestCondition(obj.(*cmapi.CertificateRequest), cmapi.CertificateRequestConditionReady)

				if (readyCondition == nil) ||
					(readyCondition.Status != cmmeta.ConditionFalse) ||
					(readyCondition.Reason != cmapi.CertificateRequestReasonPending) ||
					(readyCondition.Message != tc.issuerType+".testing.cert-manager.io \"issuer-1\" not found. Waiting for it to be created.") {
					return fmt.Errorf("incorrect ready condition: %v", readyCondition)
				}

				return nil
			}, watch.Added, watch.Modified)
			require.NoError(t, err)

			checkComplete = kubeClients.StartObjectWatch(t, ctx, cr)
			t.Log("Creating an Issuer to trigger the controller to re-reconcile the CertificateRequest")
			issuer := createIssuerForCR(t, ctx, kubeClients.Client, cr)
			t.Log("Waiting for the controller to marks the CertificateRequest as IssuerNotReady")
			err = checkComplete(func(obj runtime.Object) error {
				readyCondition := cmutil.GetCertificateRequestCondition(obj.(*cmapi.CertificateRequest), cmapi.CertificateRequestConditionReady)

				if (readyCondition == nil) ||
					(readyCondition.Status != cmmeta.ConditionFalse) ||
					(readyCondition.Reason != cmapi.CertificateRequestReasonPending) ||
					(readyCondition.Message != "Issuer is not Ready yet. No ready condition found. Waiting for it to become ready.") {
					return fmt.Errorf("incorrect ready condition: %v", readyCondition)
				}

				return nil
			}, watch.Added, watch.Modified)
			require.NoError(t, err)

			checkComplete = kubeClients.StartObjectWatch(t, ctx, cr)
			t.Log("Marking the Issuer as ready to trigger the controller to re-reconcile the CertificateRequest")
			markIssuerReady(t, ctx, kubeClients.Client, fieldOwner, issuer)
			t.Log("Waiting for the controller to marks the CertificateRequest as Ready")
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

			require.Equal(t, uint64(1), atomic.LoadUint64(&counters[testId]))
		})
	}
}

// TestCertificateRequestControllerIntegrationSetCondition runs the
// CertificateRequestController against a real Kubernetes API server.
func TestCertificateRequestControllerIntegrationSetCondition(t *testing.T) {
	fieldOwner := "cr-set-condition"

	ctx := testresource.EnsureTestDependencies(t, testcontext.ForTest(t), testresource.UnitTest)
	kubeClients := testresource.KubeClients(t, ctx)

	counter := uint64(0)
	signResult := make(chan error, 10)
	ctx = setupControllersAPIServerAndClient(t, ctx, kubeClients,
		func(mgr ctrl.Manager) controllerInterface {
			return &CertificateRequestReconciler{
				IssuerTypes:        []v1alpha1.Issuer{&api.SimpleIssuer{}},
				ClusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleClusterIssuer{}},
				FieldOwner:         fieldOwner,
				MaxRetryDuration:   time.Minute,
				EventSource:        kubeutil.NewEventStore(),
				Client:             mgr.GetClient(),
				Sign: func(ctx context.Context, cr *cmapi.CertificateRequest, _ client.Object) ([]byte, error) {
					atomic.AddUint64(&counter, 1)
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

	namespace := "clusterissuer"
	issuerType := "SimpleClusterIssuer"

	crName := types.NamespacedName{
		Name:      "cr1",
		Namespace: namespace,
	}

	t.Logf("Creating a namespace: %s", crName.Namespace)
	createNS(t, ctx, kubeClients.Client, crName.Namespace)

	cr := cmgen.CertificateRequest(
		crName.Name,
		cmgen.SetCertificateRequestNamespace(crName.Namespace),
		cmgen.SetCertificateRequestCSR([]byte("doo")),
		cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name:  "issuer-1",
			Kind:  issuerType,
			Group: api.SchemeGroupVersion.Group,
		}),
	)

	checkComplete := kubeClients.StartObjectWatch(t, ctx, cr)
	t.Log("Creating & approving the CertificateRequest")
	createApprovedCR(t, ctx, kubeClients.Client, cr)
	t.Log("Waiting for controller to mark the CertificateRequest as IssuerNotFound")
	err := checkComplete(func(obj runtime.Object) error {
		readyCondition := cmutil.GetCertificateRequestCondition(obj.(*cmapi.CertificateRequest), cmapi.CertificateRequestConditionReady)

		if (readyCondition == nil) ||
			(readyCondition.Status != cmmeta.ConditionFalse) ||
			(readyCondition.Reason != cmapi.CertificateRequestReasonPending) ||
			(readyCondition.Message != issuerType+".testing.cert-manager.io \"issuer-1\" not found. Waiting for it to be created.") {
			return fmt.Errorf("incorrect ready condition: %v", readyCondition)
		}

		return nil
	}, watch.Added, watch.Modified)
	require.NoError(t, err)

	checkComplete = kubeClients.StartObjectWatch(t, ctx, cr)
	t.Log("Creating an Issuer to trigger the controller to re-reconcile the CertificateRequest")
	issuer := createIssuerForCR(t, ctx, kubeClients.Client, cr)
	t.Log("Waiting for the controller to marks the CertificateRequest as IssuerNotReady")
	err = checkComplete(func(obj runtime.Object) error {
		readyCondition := cmutil.GetCertificateRequestCondition(obj.(*cmapi.CertificateRequest), cmapi.CertificateRequestConditionReady)

		if (readyCondition == nil) ||
			(readyCondition.Status != cmmeta.ConditionFalse) ||
			(readyCondition.Reason != cmapi.CertificateRequestReasonPending) ||
			(readyCondition.Message != "Issuer is not Ready yet. No ready condition found. Waiting for it to become ready.") {
			return fmt.Errorf("incorrect ready condition: %v", readyCondition)
		}

		return nil
	}, watch.Added, watch.Modified)
	require.NoError(t, err)

	t.Log("Marking the Issuer as ready to trigger the controller to re-reconcile the CertificateRequest")

	markIssuerReady(t, ctx, kubeClients.Client, fieldOwner, issuer)

	checkComplete = kubeClients.StartObjectWatch(t, ctx, cr)
	signResult <- signer.SetCertificateRequestConditionError{
		Err:           fmt.Errorf("[err message1]"),
		ConditionType: "[condition type]",
		Status:        cmmeta.ConditionTrue,
		Reason:        "[reason]",
	}
	err = checkComplete(func(obj runtime.Object) error {
		customCondition := cmutil.GetCertificateRequestCondition(obj.(*cmapi.CertificateRequest), "[condition type]")

		if (customCondition == nil) ||
			(customCondition.Status != cmmeta.ConditionTrue) ||
			(customCondition.Reason != "[reason]") ||
			(customCondition.Message != "[err message1]") {
			return fmt.Errorf("incorrect custom condition: %v", customCondition)
		}

		return nil
	}, watch.Added, watch.Modified)
	require.NoError(t, err)

	checkComplete = kubeClients.StartObjectWatch(t, ctx, cr)
	signResult <- signer.SetCertificateRequestConditionError{
		Err:           fmt.Errorf("[err message2]"),
		ConditionType: "[condition type]",
		Status:        cmmeta.ConditionTrue,
		Reason:        "[reason]",
	}
	err = checkComplete(func(obj runtime.Object) error {
		customCondition := cmutil.GetCertificateRequestCondition(obj.(*cmapi.CertificateRequest), "[condition type]")

		if (customCondition == nil) ||
			(customCondition.Status != cmmeta.ConditionTrue) ||
			(customCondition.Reason != "[reason]") ||
			(customCondition.Message != "[err message2]") {
			return fmt.Errorf("incorrect custom condition: %v", customCondition)
		}

		return nil
	}, watch.Added, watch.Modified)
	require.NoError(t, err)

	checkComplete = kubeClients.StartObjectWatch(t, ctx, cr)
	signResult <- nil
	t.Log("Waiting for the controller to marks the CertificateRequest as Ready")
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

	require.Equal(t, uint64(3), atomic.LoadUint64(&counter))
}

func createApprovedCR(t *testing.T, ctx context.Context, kc client.Client, cr *cmapi.CertificateRequest) {
	t.Helper()

	require.NoError(t, kc.Create(ctx, cr))
	conditions.SetCertificateRequestStatusCondition(
		&cr.Status.Conditions,
		cmapi.CertificateRequestConditionApproved,
		cmmeta.ConditionTrue,
		"ApprovedReason",
		"ApprovedMessage",
	)
	require.NoError(t, kc.Status().Update(ctx, cr))
}

func createIssuerForCR(t *testing.T, ctx context.Context, kc client.Client, cr *cmapi.CertificateRequest) v1alpha1.Issuer {
	t.Helper()

	var issuer v1alpha1.Issuer
	switch cr.Spec.IssuerRef.Kind {
	case "SimpleIssuer":
		issuer = &api.SimpleIssuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cr.Spec.IssuerRef.Name,
				Namespace: cr.Namespace,
			},
		}
	case "SimpleClusterIssuer":
		issuer = &api.SimpleClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{
				Name: cr.Spec.IssuerRef.Name,
			},
		}
	default:
		panic("unknown issuer kind")
	}
	require.NoError(t, kc.Create(ctx, issuer))
	return issuer
}

func markIssuerReady(t *testing.T, ctx context.Context, kc client.Client, fieldOwner string, issuer v1alpha1.Issuer) {
	t.Helper()

	issuerStatus := &v1alpha1.IssuerStatus{}
	conditions.SetIssuerStatusCondition(
		&issuerStatus.Conditions,
		issuer.GetGeneration(),
		cmapi.IssuerConditionReady,
		cmmeta.ConditionTrue,
		v1alpha1.IssuerConditionReasonChecked,
		"checked",
	)

	err := kubeutil.SetGroupVersionKind(kc.Scheme(), issuer)
	require.NoError(t, err)

	issuerObj, patch, err := ssaclient.GenerateIssuerStatusPatch(
		issuer,
		issuer.GetName(),
		issuer.GetNamespace(),
		issuerStatus,
	)
	require.NoError(t, err)

	err = kc.Status().Patch(ctx, issuerObj, patch, &client.SubResourcePatchOptions{
		PatchOptions: client.PatchOptions{
			FieldManager: fieldOwner,
		},
	})
	require.NoError(t, err)
}
