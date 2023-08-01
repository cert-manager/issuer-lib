/*
Copyright 2020 The cert-manager Authors.

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

package certificates

import (
	"context"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"conformance/framework"
	"conformance/framework/helper/featureset"

	. "github.com/onsi/ginkgo/v2"
)

// Suite defines a reusable conformance test suite that can be used against any
// Issuer implementation.
type Suite struct {
	// KubeClientConfig is the configuration used to connect to the Kubernetes
	// API server.
	KubeClientConfig *rest.Config

	// Name is the name of the issuer being tested, e.g. SelfSigned, CA, ACME
	// This field must be provided.
	Name string

	// IssuerRef is reference to the issuer resource that this test suite will
	// test against. All Certificate resources created by this suite will be
	// created with this issuer reference.
	IssuerRef cmmeta.ObjectReference

	// Namespace is the namespace in which the Certificate resources will be
	// created.
	Namespace string

	// DomainSuffix is a suffix used on all domain requests.
	// This is useful when the issuer being tested requires special
	// configuration for a set of domains in order for certificates to be
	// issued, such as the ACME issuer.
	// If not set, this will be defaulted to the configured 'domain' for the
	// nginx-ingress addon.
	DomainSuffix string

	// UnsupportedFeatures is a list of features that are not supported by this
	// invocation of the test suite.
	// This is useful if a particular issuers explicitly does not support
	// certain features due to restrictions in their implementation.
	UnsupportedFeatures featureset.FeatureSet

	// completed is used internally to track whether Complete() has been called
	completed bool
}

// complete will validate configuration and set default values.
func (s *Suite) complete(f *framework.Framework) {
	if s.Name == "" {
		Fail("Name must be set")
	}

	if s.IssuerRef != (cmmeta.ObjectReference{}) && s.IssuerRef.Name == "" {
		Fail("IssuerRef must be set")
	}

	if s.Namespace == "" {
		Fail("Namespace must be set")
	}

	if s.DomainSuffix == "" {
		s.DomainSuffix = "example.com"
	}

	if s.UnsupportedFeatures == nil {
		s.UnsupportedFeatures = make(featureset.FeatureSet)
	}

	s.completed = true
}

// it is called by the tests to in Define() to setup and run the test
func (s *Suite) it(f *framework.Framework, name string, fn func(context.Context, cmmeta.ObjectReference), requiredFeatures ...featureset.Feature) {
	if !s.checkFeatures(requiredFeatures...) {
		return
	}
	It(name, func(ctx context.Context) {
		fn(ctx, s.IssuerRef)
	})
}

// checkFeatures is a helper function that is used to ensure that the features
// required for a given test case are supported by the suite.
// It will return 'true' if all features are supported and the test should run,
// or return 'false' if any required feature is not supported.
func (s *Suite) checkFeatures(fs ...featureset.Feature) bool {
	for _, f := range fs {
		if s.UnsupportedFeatures.Contains(f) {
			return false
		}
	}

	return true
}
