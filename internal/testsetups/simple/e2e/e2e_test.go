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

package e2e_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"testing"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/util/retry"

	"github.com/cert-manager/issuer-lib/internal/tests/testcontext"
	"github.com/cert-manager/issuer-lib/internal/tests/testresource"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/testutil"
)

func TestSimpleCertificate(t *testing.T) {
	ctx := testresource.EnsureTestDependencies(t, testcontext.ForTest(t), testresource.EndToEndTest)

	kubeClients := testresource.KubeClients(t, ctx)

	namespace, cleanup := kubeClients.SetupNamespace(t, ctx)
	defer cleanup()

	issuer := testutil.SimpleIssuer("issuer-test",
		testutil.SetSimpleIssuerNamespace(namespace),
	)

	certificate := cmgen.Certificate(
		"test-cert",
		cmgen.SetCertificateNamespace(namespace),
		cmgen.SetCertificateCommonName("test.com"),
		cmgen.SetCertificateSecretName("aaaaaaaa"),
		cmgen.SetCertificateIssuer(v1.ObjectReference{
			Group: issuer.GroupVersionKind().Group,
			Kind:  issuer.Kind,
			Name:  issuer.Name,
		}),
	)

	err := kubeClients.Client.Create(ctx, issuer)
	require.NoError(t, err)

	complete := kubeClients.StartObjectWatch(t, ctx, certificate)

	err = kubeClients.Client.Create(ctx, certificate)
	require.NoError(t, err)

	err = complete(func(cert runtime.Object) error {
		condition := cmutil.GetCertificateCondition(cert.(*cmapi.Certificate), cmapi.CertificateConditionReady)

		if (condition == nil) ||
			(condition.Status != v1.ConditionTrue) {
			return fmt.Errorf("ready condition is not correct (yet): %v", condition)
		}

		return nil
	}, watch.Added, watch.Modified)
	require.NoError(t, err)
}

func TestSimpleCertificateSigningRequest(t *testing.T) {
	ctx := testresource.EnsureTestDependencies(t, testcontext.ForTest(t), testresource.EndToEndTest)

	kubeClients := testresource.KubeClients(t, ctx)

	csrName := "test-" + randStringRunes(20)

	clusterIssuer := testutil.SimpleClusterIssuer("cluster-issuer-" + csrName)

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	csrBlob, err := cmgen.CSRWithSigner(privateKey,
		cmgen.SetCSRCommonName("test.com"),
	)
	require.NoError(t, err)

	csr := cmgen.CertificateSigningRequest(
		"csr-"+csrName,
		cmgen.SetCertificateSigningRequestDuration("1h"),
		cmgen.SetCertificateSigningRequestRequest(csrBlob),
		cmgen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature}),
		cmgen.SetCertificateSigningRequestSignerName(fmt.Sprintf("simpleclusterissuers.issuer.cert-manager.io/%s", clusterIssuer.Name)),
	)

	err = kubeClients.Client.Create(ctx, clusterIssuer)
	require.NoError(t, err)

	complete := kubeClients.StartObjectWatch(t, ctx, csr)

	err = kubeClients.Client.Create(ctx, csr)
	require.NoError(t, err)

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := kubeClients.Client.Get(ctx, types.NamespacedName{Name: csr.Name}, csr); err != nil {
			return err
		}

		nowTime := metav1.NewTime(time.Now())

		csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:           certificatesv1.CertificateApproved,
			Reason:         "test",
			Message:        "test",
			LastUpdateTime: nowTime,
			Status:         corev1.ConditionTrue,
		})

		return kubeClients.Client.SubResource("approval").Update(ctx, csr)
	})
	require.NoError(t, err)

	err = complete(func(obj runtime.Object) error {
		csr := obj.(*certificatesv1.CertificateSigningRequest)

		if len(csr.Status.Certificate) == 0 {
			return fmt.Errorf("certificate is not set (yet): %v", csr.Status.Certificate)
		}

		return nil
	}, watch.Added, watch.Modified)
	require.NoError(t, err)
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")

// RandStringRunes - generate random string using random int
func randStringRunes(n int) string {
	b := make([]rune, n)
	l := len(letterRunes)
	for i := range b {
		b[i] = letterRunes[mathrand.Intn(l)]
	}
	return string(b)
}
