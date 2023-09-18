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
	"os"
	"testing"

	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/cert-manager/issuer-lib/internal/tests/testresource"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/api"
)

func createNS(t *testing.T, ctx context.Context, kc client.Client, nsName string) {
	t.Helper()

	ns := corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
		},
	}
	require.NoError(t, kc.Create(ctx, &ns))
}

type controllerInterface interface {
	SetupWithManager(ctx context.Context, mgr ctrl.Manager) error
}

func setupControllersAPIServerAndClient(t *testing.T, parentCtx context.Context, kubeClients *testresource.OwnedKubeClients, controller func(mgr ctrl.Manager) controllerInterface) context.Context {
	t.Helper()

	eg, gctx := errgroup.WithContext(parentCtx)
	t.Cleanup(func() {
		t.Log("Waiting for controller manager to exit")
		require.NoError(t, eg.Wait())
	})

	require.NoError(t, corev1.AddToScheme(kubeClients.Scheme))

	logger := logrtesting.NewTestLoggerWithOptions(t, logrtesting.Options{LogTimestamp: true, Verbosity: 10})
	ctrl.SetLogger(logger)
	klog.SetLogger(logger)

	t.Log("Installing cert-manager CRDs")
	_, err := kubeClients.InstallCRDs(envtest.CRDInstallOptions{
		Scheme: kubeClients.Scheme,
		Paths: []string{
			os.Getenv("SIMPLE_CRDS"),
			os.Getenv("CERT_MANAGER_CRDS"),
		},
		ErrorIfPathMissing: true,
	})
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, setupCertificateRequestReconcilerScheme(scheme))
	require.NoError(t, api.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	t.Log("Creating a controller manager")
	mgr, err := ctrl.NewManager(kubeClients.Rest, ctrl.Options{
		Scheme:         scheme,
		Logger:         logger,
		LeaderElection: false,
		Metrics: server.Options{
			BindAddress: "0",
		},
	})
	require.NoError(t, err)

	t.Log("Setting up controller")
	require.NoError(t, controller(mgr).SetupWithManager(gctx, mgr))

	mgrCtx, cancel := context.WithCancel(gctx)
	t.Cleanup(cancel)

	t.Log("Starting the controller manager")
	eg.Go(func() error {
		return mgr.Start(mgrCtx)
	})

	return gctx
}
