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

package testresource

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	goruntime "runtime"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/cert-manager/issuer-lib/internal/kubeutil"
	"github.com/cert-manager/issuer-lib/internal/testapi/api"
)

type OwnedKubeClients struct {
	EnvTest    *envtest.Environment
	Rest       *rest.Config
	Scheme     *runtime.Scheme
	KubeClient *kubernetes.Clientset
	Client     client.WithWatch
}

func KubeClients(tb testing.TB, ctx context.Context) *OwnedKubeClients {
	tb.Helper()

	scheme := runtime.NewScheme()
	require.NoError(tb, corev1.AddToScheme(scheme))
	require.NoError(tb, certificatesv1.AddToScheme(scheme))
	require.NoError(tb, cmapi.AddToScheme(scheme))
	require.NoError(tb, api.AddToScheme(scheme))

	testKubernetes := &OwnedKubeClients{
		Scheme: scheme,
	}

	switch CurrentTestMode(ctx) {
	case UnitTest:
		testKubernetes.initTestEnv(tb, testKubernetes.Scheme)
	case EndToEndTest:
		testKubernetes.initExistingKubernetes(tb, testKubernetes.Scheme)
	default:
		tb.Fatalf("unknown test mode specified")
	}

	kubeClientset, err := kubernetes.NewForConfig(testKubernetes.Rest)
	require.NoError(tb, err)

	testKubernetes.KubeClient = kubeClientset

	controllerClient, err := client.NewWithWatch(testKubernetes.Rest, client.Options{Scheme: scheme})
	require.NoError(tb, err)

	testKubernetes.Client = controllerClient

	return testKubernetes
}

func (k *OwnedKubeClients) initTestEnv(tb testing.TB, scheme *runtime.Scheme) {
	tb.Helper()

	k.EnvTest = &envtest.Environment{
		Scheme: scheme,
	}

	tb.Log("Creating a Kubernetes API server")
	cfg, err := k.EnvTest.Start()
	require.NoError(tb, err)

	tb.Cleanup(func() {
		tb.Log("Waiting for testEnv to exit")
		require.NoError(tb, k.EnvTest.Stop())
	})

	k.Rest = cfg
}

func (k *OwnedKubeClients) initExistingKubernetes(tb testing.TB, scheme *runtime.Scheme) {
	tb.Helper()

	kubeConfig, err := config.GetConfigWithContext("")
	require.NoError(tb, err)

	k.Rest = kubeConfig
}

func (k *OwnedKubeClients) InstallCRDs(options envtest.CRDInstallOptions) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	return envtest.InstallCRDs(k.Rest, options)
}

type CompleteFunc func(fn func(runtime.Object) error, eventTypes ...watch.EventType) error

// StartObjectWatch starts a watch for the provided object,
// the returned function should be used to wait for a condition
// to succeed. The watch will start after calling this function.
// This means that the completion function can respond to events
// received before calling the complete function but after calling
// StartObjectWatch.
func (k *OwnedKubeClients) StartObjectWatch(
	tb testing.TB,
	ctx context.Context,
	object client.Object,
) CompleteFunc {
	tb.Helper()

	fields := map[string]string{}
	if name := object.GetName(); name != "" {
		fields["metadata.name"] = name
	}
	if namespace := object.GetNamespace(); namespace != "" {
		fields["metadata.namespace"] = namespace
	}

	err := kubeutil.SetGroupVersionKind(k.Scheme, object)
	require.NoError(tb, err)

	listObj, err := kubeutil.NewListObject(k.Scheme, object.GetObjectKind().GroupVersionKind())
	require.NoError(tb, err)

	watcher, startWatchError := k.Client.Watch(ctx, listObj, client.MatchingFields(fields), client.Limit(1))
	stopped := (startWatchError != nil)
	checkFunctionCalledBeforeCleanup(tb, "StartObjectWatch", "CompleteFunc", &stopped)

	stop := func() {
		if !stopped {
			watcher.Stop()
			stopped = true
		}
	}

	return func(fn func(runtime.Object) error, eventTypes ...watch.EventType) error {
		if startWatchError != nil {
			return startWatchError
		}

		defer stop()

		if fn == nil {
			return nil
		}

		var lastError error
		for {
			var event watch.Event
			select {
			case <-ctx.Done():
				if lastError == nil {
					lastError = ctx.Err()
				}
				return lastError
			case event = <-watcher.ResultChan():
			}

			found := false
		CheckLoop:
			for _, eventType := range eventTypes {
				if eventType == event.Type {
					found = true
					break CheckLoop
				}
			}

			if !found {
				continue
			}

			fnErr := fn(event.Object)
			if fnErr == nil {
				return nil
			}
			// we only want to overwrite the error if it is not a DeadlineExceeded error
			if lastError == nil || !errors.Is(fnErr, context.DeadlineExceeded) {
				lastError = fnErr
			}
		}
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func (k *OwnedKubeClients) SetupNamespace(tb testing.TB, ctx context.Context) (string, context.CancelFunc) {
	tb.Helper()

	namespace := randStringBytes(15)

	removeNamespace := func(cleanupCtx context.Context) (bool, error) {
		err := k.KubeClient.CoreV1().Namespaces().Delete(cleanupCtx, namespace, metav1.DeleteOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	}

	cleanupExisting := func(cleanupCtx context.Context) error {
		complete := k.StartObjectWatch(tb, cleanupCtx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})
		defer require.NoError(tb, complete(nil))

		if notFound, err := removeNamespace(cleanupCtx); err != nil {
			return err
		} else if notFound {
			return nil
		}

		return complete(func(o runtime.Object) error {
			return nil
		}, watch.Deleted)
	}
	require.NoError(tb, cleanupExisting(ctx))

	namespaceObj := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}
	_, err := k.KubeClient.CoreV1().Namespaces().Create(ctx, namespaceObj, metav1.CreateOptions{})
	require.NoError(tb, err)

	stopped := false
	checkFunctionCalledBeforeCleanup(tb, "SetupNamespace", "CancelFunc", &stopped)

	return namespace, func() {
		defer func() { stopped = true }()

		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := removeNamespace(cleanupCtx)
		require.NoError(tb, err)
	}
}

func checkFunctionCalledBeforeCleanup(tb testing.TB, name string, funcname string, stopped *bool) {
	tb.Helper()

	_, file, no, ok := goruntime.Caller(2)
	message := fmt.Sprintf("%s's %s was not called", name, funcname)
	if ok {
		message += fmt.Sprintf(", %s called at %s#%d", name, file, no)
	}
	tb.Cleanup(func() {
		if !*stopped {
			panic(message)
		}
	})
}
