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
	"fmt"
	"testing"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/cert-manager/issuer-lib/internal/tests/testcontext"
	"github.com/cert-manager/issuer-lib/internal/tests/testresource"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/testutil"
)

func TestSimple(t *testing.T) {
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
