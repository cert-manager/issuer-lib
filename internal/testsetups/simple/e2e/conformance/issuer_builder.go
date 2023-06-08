package conformance

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crtclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/issuer-lib/conformance/framework"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

type issuerBuilder struct {
	clusterResourceNamespace string
	prototype                *unstructured.Unstructured
}

func newIssuerBuilder(issuerKind string) *issuerBuilder {
	return &issuerBuilder{
		clusterResourceNamespace: "test-namespace",
		prototype: &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "testing.cert-manager.io/api",
				"kind":       issuerKind,
				"spec":       map[string]interface{}{},
			},
		},
	}
}

func (o *issuerBuilder) nameForTestObject(f *framework.Framework, suffix string) types.NamespacedName {
	namespace := f.Namespace.Name
	if o.prototype.GetKind() == "ClusterIssuer" {
		namespace = o.clusterResourceNamespace
	}
	return types.NamespacedName{
		Name:      fmt.Sprintf("%s-%s", f.Namespace.Name, suffix),
		Namespace: namespace,
	}
}

func (o *issuerBuilder) secretAndIssuerForTest(f *framework.Framework) (*corev1.Secret, *unstructured.Unstructured, error) {
	secretName := o.nameForTestObject(f, "credentials")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName.Name,
			Namespace: secretName.Namespace,
		},
		StringData: map[string]string{},
	}

	issuerName := o.nameForTestObject(f, "issuer")
	issuer := o.prototype.DeepCopy()
	issuer.SetName(issuerName.Name)
	issuer.SetNamespace(issuerName.Namespace)
	err := unstructured.SetNestedField(issuer.Object, secret.Name, "spec", "authSecretName")

	return secret, issuer, err
}

func (o *issuerBuilder) create(f *framework.Framework, ctx context.Context) cmmeta.ObjectReference {
	By("Creating an Issuer")
	secret, issuer, err := o.secretAndIssuerForTest(f)
	Expect(err).NotTo(HaveOccurred(), "failed to initialise test objects")

	crt, err := crtclient.New(f.KubeClientConfig, crtclient.Options{})
	Expect(err).NotTo(HaveOccurred(), "failed to create controller-runtime client")

	err = crt.Create(ctx, secret)
	Expect(err).NotTo(HaveOccurred(), "failed to create secret")

	err = crt.Create(ctx, issuer)
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer")

	return cmmeta.ObjectReference{
		Group: issuer.GroupVersionKind().Group,
		Kind:  issuer.GroupVersionKind().Kind,
		Name:  issuer.GetName(),
	}
}

func (o *issuerBuilder) delete(f *framework.Framework, ctx context.Context, _ cmmeta.ObjectReference) {
	By("Deleting the issuer")

	crt, err := crtclient.New(f.KubeClientConfig, crtclient.Options{})
	Expect(err).NotTo(HaveOccurred(), "failed to create controller-runtime client")

	secret, issuer, err := o.secretAndIssuerForTest(f)
	Expect(err).NotTo(HaveOccurred(), "failed to initialise test objects")

	err = crt.Delete(ctx, issuer)
	Expect(err).NotTo(HaveOccurred(), "failed to delete issuer")

	err = crt.Delete(ctx, secret)
	Expect(err).NotTo(HaveOccurred(), "failed to delete secret")
}
