package conformance

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/cert-manager/issuer-lib/internal/tests/testcontext"
	"github.com/cert-manager/issuer-lib/internal/tests/testresource"
)

func TestConformance(t *testing.T) {
	_ = testresource.EnsureTestDependencies(t, testcontext.ForTest(t), testresource.EndToEndTest)

	gomega.RegisterFailHandler(ginkgo.Fail)

	ginkgo.RunSpecs(t, "cert-manager conformance suite")
}
