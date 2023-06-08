package conformance

import (
	"context"
	"fmt"
	"testing"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/issuer-lib/conformance/certificates"
	"github.com/cert-manager/issuer-lib/conformance/certificatesigningrequests"
	"github.com/cert-manager/issuer-lib/conformance/framework"
	"github.com/cert-manager/issuer-lib/conformance/framework/helper/featureset"
	"github.com/cert-manager/issuer-lib/internal/tests/testresource"
)

type mockTest struct {
	testing.TB
}

func (m *mockTest) Helper() {}

var _ = framework.ConformanceDescribe("Certificates", func() {
	t := &mockTest{}
	ctx := testresource.EnsureTestDependencies(t, context.TODO(), testresource.EndToEndTest)
	kubeClients := testresource.KubeClients(t, ctx)

	unsupportedFeatures := featureset.NewFeatureSet(
		featureset.DurationFeature,
		featureset.KeyUsagesFeature,
		featureset.SaveCAToSecret,
		featureset.Ed25519FeatureSet,
		featureset.IssueCAFeature,
		featureset.LiteralSubjectFeature,
	)

	issuerBuilder := newIssuerBuilder("SimpleIssuer")
	(&certificates.Suite{
		KubeClientConfig:    kubeClients.Rest,
		Name:                "External Issuer",
		CreateIssuerFunc:    issuerBuilder.create,
		DeleteIssuerFunc:    issuerBuilder.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()

	clusterIssuerBuilder := newIssuerBuilder("SimpleClusterIssuer")
	(&certificates.Suite{
		KubeClientConfig:    kubeClients.Rest,
		Name:                "External ClusterIssuer",
		CreateIssuerFunc:    clusterIssuerBuilder.create,
		DeleteIssuerFunc:    clusterIssuerBuilder.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()
})

var _ = framework.ConformanceDescribe("CertificateSigningRequests", func() {
	t := &mockTest{}
	ctx := testresource.EnsureTestDependencies(t, context.TODO(), testresource.EndToEndTest)
	kubeClients := testresource.KubeClients(t, ctx)

	unsupportedFeatures := featureset.NewFeatureSet(
		featureset.DurationFeature,
		featureset.KeyUsagesFeature,
		featureset.SaveCAToSecret,
		featureset.Ed25519FeatureSet,
		featureset.IssueCAFeature,
		featureset.LiteralSubjectFeature,
	)

	clusterIssuerBuilder := newIssuerBuilder("SimpleClusterIssuer")
	(&certificatesigningrequests.Suite{
		KubeClientConfig: kubeClients.Rest,
		Name:             "External ClusterIssuer",
		CreateIssuerFunc: func(f *framework.Framework, ctx context.Context) string {
			ref := clusterIssuerBuilder.create(f, ctx)
			return fmt.Sprintf("simpleclusterissuers.issuer.cert-manager.io/%s", ref.Name)
		},
		DeleteIssuerFunc: func(f *framework.Framework, ctx context.Context, s string) {
			ref := cmmeta.ObjectReference{
				Group: "testing.cert-manager.io",
				Kind:  "SimpleClusterIssuer",
				Name:  s,
			}
			clusterIssuerBuilder.delete(f, ctx, ref)
		},
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()
})

var _ = framework.ConformanceDescribe("RBAC", func() {
	t := &mockTest{}
	ctx := testresource.EnsureTestDependencies(t, context.TODO(), testresource.EndToEndTest)
	kubeClients := testresource.KubeClients(t, ctx)

	unsupportedFeatures := featureset.NewFeatureSet(
		featureset.DurationFeature,
		featureset.KeyUsagesFeature,
		featureset.SaveCAToSecret,
		featureset.Ed25519FeatureSet,
		featureset.IssueCAFeature,
		featureset.LiteralSubjectFeature,
	)

	issuerBuilder := newIssuerBuilder("SimpleIssuer")
	(&certificates.Suite{
		KubeClientConfig:    kubeClients.Rest,
		Name:                "External Issuer",
		CreateIssuerFunc:    issuerBuilder.create,
		DeleteIssuerFunc:    issuerBuilder.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()

	clusterIssuerBuilder := newIssuerBuilder("SimpleClusterIssuer")
	(&certificates.Suite{
		KubeClientConfig:    kubeClients.Rest,
		Name:                "External ClusterIssuer",
		CreateIssuerFunc:    clusterIssuerBuilder.create,
		DeleteIssuerFunc:    clusterIssuerBuilder.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()
})
