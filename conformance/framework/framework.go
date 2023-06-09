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
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	certmgrscheme "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/scheme"
	api "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	gwapi "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/cert-manager/issuer-lib/conformance/framework/helper"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// TODO: not all this code is required to be externally accessible. Separate the
// bits that do and the bits that don't. Perhaps we should have an external
// testing lib shared across projects?
// TODO: this really should be done somewhere in cert-manager proper
var Scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(kscheme.AddToScheme(Scheme))
	utilruntime.Must(certmgrscheme.AddToScheme(Scheme))
	utilruntime.Must(apiext.AddToScheme(Scheme))
	utilruntime.Must(apireg.AddToScheme(Scheme))
}

// Framework supports common operations used by e2e tests; it will keep a client & a namespace for you.
type Framework struct {
	BaseName string

	// KubeClientConfig which was used to create the connection.
	KubeClientConfig *rest.Config

	// Kubernetes API clientsets
	KubeClientSet          kubernetes.Interface
	GWClientSet            gwapi.Interface
	CertManagerClientSet   clientset.Interface
	APIExtensionsClientSet apiextcs.Interface

	// controller-runtime client for newer controllers
	CRClient crclient.Client

	// Namespace in which all test resources should reside
	Namespace *api.Namespace

	// To make sure that this framework cleans up after itself, no matter what,
	// we install a Cleanup action before each test and clear it after.  If we
	// should abort, the AfterSuite hook should run all Cleanup actions.
	cleanupHandle CleanupActionHandle

	helper *helper.Helper
}

// NewFramework makes a new framework and sets up a BeforeEach/AfterEach for
// you (you can write additional before/after each functions).
// It uses the config provided to it for the duration of the tests.
func NewFramework(baseName string, kubeClientConfig *rest.Config) *Framework {
	f := &Framework{
		KubeClientConfig: kubeClientConfig,
		BaseName:         baseName,
	}

	f.helper = helper.NewHelper(kubeClientConfig)
	BeforeEach(f.BeforeEach)
	AfterEach(f.AfterEach)

	return f
}

// BeforeEach gets a client and makes a namespace.
func (f *Framework) BeforeEach() {
	f.cleanupHandle = AddCleanupAction(f.AfterEach)

	var err error
	kubeConfig := rest.CopyConfig(f.KubeClientConfig)

	kubeConfig.Burst = 9000
	kubeConfig.QPS = 9000

	f.KubeClientConfig = kubeConfig

	f.KubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating an API extensions client")
	f.APIExtensionsClientSet, err = apiextcs.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating a cert manager client")
	f.CertManagerClientSet, err = clientset.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating a controller-runtime client")
	f.CRClient, err = crclient.New(kubeConfig, crclient.Options{Scheme: Scheme})
	Expect(err).NotTo(HaveOccurred())

	By("Creating a gateway-api client")
	f.GWClientSet, err = gwapi.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Building a namespace api object")
	f.Namespace, err = f.CreateKubeNamespace(f.BaseName)
	Expect(err).NotTo(HaveOccurred())

	By("Using the namespace " + f.Namespace.Name)

	By("Building a ResourceQuota api object")
	_, err = f.CreateKubeResourceQuota()
	Expect(err).NotTo(HaveOccurred())

	f.helper.CMClient = f.CertManagerClientSet
	f.helper.KubeClient = f.KubeClientSet
}

// AfterEach deletes the namespace, after reading its events.
func (f *Framework) AfterEach() {
	RemoveCleanupAction(f.cleanupHandle)

	By("Deleting test namespace")
	err := f.DeleteKubeNamespace(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())
}

func (f *Framework) Helper() *helper.Helper {
	return f.helper
}

// CertManagerDescribe is a wrapper function for ginkgo describe. Adds namespacing.
func CertManagerDescribe(text string, body func()) bool {
	return Describe("[cert-manager] "+text, body)
}

func ConformanceDescribe(text string, body func()) bool {
	return Describe("[Conformance] "+text, body)
}
