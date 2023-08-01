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

package framework

import (
	"context"

	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	certmgrscheme "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/scheme"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"conformance/framework/helper"
	e2eutil "conformance/util"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	log.SetLogger(GinkgoLogr)
}

// Framework supports common operations used by e2e tests; it will keep a client & a namespace for you.
type Framework struct {
	BaseName string

	// KubeClientConfig which was used to create the connection.
	KubeClientConfig *rest.Config

	// Kubernetes API clientsets
	KubeClientSet          kubernetes.Interface
	CertManagerClientSet   clientset.Interface
	APIExtensionsClientSet apiextcs.Interface

	// controller-runtime client for newer controllers
	CRClient crclient.Client

	// Namespace in which all resources are created for this test suite.
	Namespace string

	// CleanupLabel is a label that should be applied to all resources created
	// by this test suite. It is used to clean up all resources at the end of
	// the test suite.
	CleanupLabel string

	// cleanupResourceTypes is a list of all resource types that should be cleaned
	// up after each test.
	cleanupResourceTypes []crclient.Object

	helper *helper.Helper
}

// NewFramework makes a new framework and sets up a BeforeEach/AfterEach for
// you (you can write additional before/after each functions).
// It uses the config provided to it for the duration of the tests.
func NewFramework(
	baseName string,
	kubeClientConfig *rest.Config,
	namespace string,
	cleanupResourceTypes []crclient.Object,
) *Framework {
	f := &Framework{
		BaseName:             baseName,
		KubeClientConfig:     kubeClientConfig,
		Namespace:            namespace,
		cleanupResourceTypes: cleanupResourceTypes,
	}

	f.helper = helper.NewHelper()
	BeforeEach(f.BeforeEach)
	AfterEach(f.AfterEach)

	return f
}

// BeforeEach initializes all clients.
func (f *Framework) BeforeEach(ctx context.Context) {
	f.CleanupLabel = "cm-conformance-cleanup-" + e2eutil.RandStringRunes(10)

	var err error
	kubeConfig := rest.CopyConfig(f.KubeClientConfig)

	f.KubeClientConfig = kubeConfig

	f.KubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating a cert manager client")
	f.CertManagerClientSet, err = clientset.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating a controller-runtime client")
	scheme := runtime.NewScheme()
	Expect(kscheme.AddToScheme(scheme)).NotTo(HaveOccurred())
	Expect(certmgrscheme.AddToScheme(scheme)).NotTo(HaveOccurred())
	Expect(apiext.AddToScheme(scheme)).NotTo(HaveOccurred())
	Expect(apireg.AddToScheme(scheme)).NotTo(HaveOccurred())

	f.CRClient, err = crclient.New(kubeConfig, crclient.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	if f.Namespace != "" {
		By("Check that the namespace " + f.Namespace + " exists")
		_, err = f.KubeClientSet.CoreV1().Namespaces().Get(ctx, f.Namespace, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
	}

	f.helper.CMClient = f.CertManagerClientSet
	f.helper.KubeClient = f.KubeClientSet
}

func (f *Framework) AfterEach(ctx context.Context) {
	for _, obj := range f.cleanupResourceTypes {
		By("Deleting " + obj.GetObjectKind().GroupVersionKind().String() + " resources")
		err := f.CRClient.DeleteAllOf(
			ctx,
			obj,
			crclient.InNamespace(f.Namespace),
			crclient.MatchingLabels{f.CleanupLabel: "true"},
		)
		Expect(err).NotTo(HaveOccurred())
	}
}

func (f *Framework) Helper() *helper.Helper {
	return f.helper
}

func ConformanceDescribe(text string, body func()) bool {
	return Describe("[Conformance] "+text, body)
}
