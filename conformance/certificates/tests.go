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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/issuer-lib/conformance/framework"
	"github.com/cert-manager/issuer-lib/conformance/framework/helper/featureset"
	"github.com/cert-manager/issuer-lib/conformance/framework/helper/validation"
	"github.com/cert-manager/issuer-lib/conformance/framework/helper/validation/certificates"
	e2eutil "github.com/cert-manager/issuer-lib/conformance/util"
)

// Define defines simple conformance tests that can be run against any issuer type.
// If Complete has not been called on this Suite before Define, it will be
// automatically called.
func (s *Suite) Define() {
	Describe("with issuer type "+s.Name, func() {
		ctx := context.Background()
		f := framework.NewFramework("certificates", s.KubeClientConfig)

		sharedIPAddress := "127.0.0.1"

		// Wrap this in a BeforeEach else flags will not have been parsed and
		// f.Config will not be populated at the time that this code is run.
		BeforeEach(func() {
			if s.completed {
				return
			}
			s.complete(f)
		})

		s.it(f, "should issue a basic, defaulted certificate for a single distinct DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN)

		s.it(f, "should issue a CA certificate with the CA basicConstraint set", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IsCA:       true,
					IssuerRef:  issuerRef,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.IssueCAFeature)

		s.it(f, "should issue an ECDSA, defaulted certificate for a single distinct DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
					},
					DNSNames:  []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef: issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.ECDSAFeature, featureset.OnlySAN)

		s.it(f, "should issue an Ed25519, defaulted certificate for a single distinct DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.Ed25519KeyAlgorithm,
					},
					DNSNames:  []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef: issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN, featureset.Ed25519FeatureSet)

		s.it(f, "should issue a basic, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + e2eutil.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					CommonName: cn,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature)

		s.it(f, "should issue a basic, defaulted certificate for a single distinct DNS Name with a literal subject", func(issuerRef cmmeta.ObjectReference) {
			// framework.RequireFeatureGate(f, utilfeature.DefaultFeatureGate, feature.LiteralCertificateSubject)
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			host := fmt.Sprintf("*.%s.foo-long.bar.com", e2eutil.RandStringRunes(10))
			literalSubject := fmt.Sprintf("CN=%s,OU=FooLong,OU=Bar,OU=Baz,OU=Dept.,O=Corp.", host)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:     "testcert-tls",
					IssuerRef:      issuerRef,
					LiteralSubject: literalSubject,
					DNSNames:       []string{host},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")

			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			//type ValidationFunc func(certificate *cmapi.Certificate, secret *corev1.Secret) error
			valFunc := func(certificate *cmapi.Certificate, secret *corev1.Secret) error {
				certBytes, ok := secret.Data[corev1.TLSCertKey]
				if !ok {
					return fmt.Errorf("no certificate data found for Certificate %q (secret %q)", certificate.Name, certificate.Spec.SecretName)
				}

				createdCert, err := pki.DecodeX509CertificateBytes(certBytes)
				if err != nil {
					return err
				}

				var dns pkix.RDNSequence
				rest, err := asn1.Unmarshal(createdCert.RawSubject, &dns)

				if err != nil {
					return err
				}

				rdnSeq, err2 := pki.UnmarshalSubjectStringToRDNSequence(literalSubject)

				if err2 != nil {
					return err2
				}

				fmt.Fprintln(GinkgoWriter, "cert", base64.StdEncoding.EncodeToString(createdCert.RawSubject), dns, err, rest)
				if !reflect.DeepEqual(rdnSeq, dns) {
					return fmt.Errorf("generated certificate's subject [%s] does not match expected subject [%s]", dns.String(), literalSubject)
				}
				return nil
			}

			By("Validating the issued Certificate...")

			err = f.Helper().ValidateCertificate(testCertificate, valFunc)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.LiteralSubjectFeature)

		s.it(f, "should issue an ECDSA, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + e2eutil.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
					},
					CommonName: cn,
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.ECDSAFeature, featureset.CommonNameFeature)

		s.it(f, "should issue an Ed25519, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + e2eutil.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.Ed25519KeyAlgorithm,
					},
					CommonName: cn,
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.Ed25519FeatureSet, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines an IP Address", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:  "testcert-tls",
					IPAddresses: []string{sharedIPAddress},
					IssuerRef:   issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.IPAddressFeature)

		s.it(f, "should issue a certificate that defines a DNS Name and IP Address", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:  "testcert-tls",
					IPAddresses: []string{sharedIPAddress},
					DNSNames:    []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:   issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN, featureset.IPAddressFeature)

		s.it(f, "should issue a certificate that defines a Common Name and IP Address", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + e2eutil.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:  "testcert-tls",
					CommonName:  cn,
					IPAddresses: []string{sharedIPAddress},
					IssuerRef:   issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature, featureset.IPAddressFeature)

		s.it(f, "should issue a certificate that defines an Email Address", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:     "testcert-tls",
					EmailAddresses: []string{"alice@example.com"},
					IssuerRef:      issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.EmailSANsFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that defines a Common Name and URI SAN", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + e2eutil.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: cn,
					URIs:       []string{"spiffe://cluster.local/ns/sandbox/sa/foo"},
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.URISANsFeature, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a 2 distinct DNS Names with one copied to the Common Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: e2eutil.RandomSubdomain(s.DomainSuffix),
					IssuerRef:  issuerRef,
				},
			}
			testCertificate.Spec.DNSNames = []string{
				testCertificate.Spec.CommonName, e2eutil.RandomSubdomain(s.DomainSuffix),
			}

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a distinct DNS Name and another distinct Common Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: e2eutil.RandomSubdomain(s.DomainSuffix),
					IssuerRef:  issuerRef,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
				},
			}

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a DNS Name and sets a duration", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					Duration: &metav1.Duration{
						Duration: time.Hour * 896,
					},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.DurationFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that defines a wildcard DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{"*." + e2eutil.RandomSubdomain(s.DomainSuffix)},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.WildcardsFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that includes only a URISANs name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					URIs: []string{
						"spiffe://cluster.local/ns/sandbox/sa/foo",
					},
					IssuerRef: issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.URISANsFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that includes arbitrary key usages", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:  issuerRef,
					Usages: []cmapi.KeyUsage{
						cmapi.UsageSigning,
						cmapi.UsageDataEncipherment,
						cmapi.UsageServerAuth,
						cmapi.UsageClientAuth,
					},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")

			validations := []certificates.ValidationFunc{
				certificates.ExpectKeyUsageExtKeyUsageClientAuth,
				certificates.ExpectKeyUsageExtKeyUsageServerAuth,
				certificates.ExpectKeyUsageUsageDigitalSignature,
				certificates.ExpectKeyUsageUsageDataEncipherment,
			}
			validations = append(validations, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)

			err = f.Helper().ValidateCertificate(testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.KeyUsagesFeature, featureset.OnlySAN)

		s.it(f, "should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())

			By("Deleting existing certificate data in Secret")
			sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).
				Get(ctx, testCertificate.Spec.SecretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get secret containing signed certificate key pair data")

			sec = sec.DeepCopy()
			crtPEM1 := sec.Data[corev1.TLSCertKey]
			crt1, err := pki.DecodeX509CertificateBytes(crtPEM1)
			Expect(err).NotTo(HaveOccurred(), "failed to get decode first signed certificate data")

			sec.Data[corev1.TLSCertKey] = []byte{}

			_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(ctx, sec, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to update secret by deleting the signed certificate data")

			By("Waiting for the Certificate to re-issue a certificate")
			sec, err = f.Helper().WaitForSecretCertificateData(f.Namespace.Name, sec.Name, time.Minute*8)
			Expect(err).NotTo(HaveOccurred(), "failed to wait for secret to have a valid 2nd certificate")

			crtPEM2 := sec.Data[corev1.TLSCertKey]
			crt2, err := pki.DecodeX509CertificateBytes(crtPEM2)
			Expect(err).NotTo(HaveOccurred(), "failed to get decode second signed certificate data")

			By("Ensuing both certificates are signed by same private key")
			match, err := pki.PublicKeysEqual(crt1.PublicKey, crt2.PublicKey)
			Expect(err).NotTo(HaveOccurred(), "failed to check public keys of both signed certificates")

			if !match {
				Fail("Both signed certificates not signed by same private key")
			}
		}, featureset.ReusePrivateKeyFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that defines a long domain", func(issuerRef cmmeta.ObjectReference) {
			// the maximum length of a single segment of the domain being requested
			const maxLengthOfDomainSegment = 63

			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{e2eutil.RandomSubdomainLength(s.DomainSuffix, maxLengthOfDomainSegment)},
					IssuerRef:  issuerRef,
				},
			}
			validations := validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Sanity-check the issued Certificate")
			err = f.Helper().ValidateCertificate(testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN, featureset.LongDomainFeatureSet)

		s.it(f, "should allow updating an existing certificate with a new DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:  issuerRef,
				},
			}
			validations := validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be ready")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Sanity-check the issued Certificate")
			err = f.Helper().ValidateCertificate(testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())

			By("Updating the Certificate after having added an additional dnsName")
			newDNSName := e2eutil.RandomSubdomain(s.DomainSuffix)
			retry.RetryOnConflict(retry.DefaultRetry, func() error {
				err = f.CRClient.Get(context.Background(), types.NamespacedName{Name: testCertificate.Name, Namespace: testCertificate.Namespace}, testCertificate)
				if err != nil {
					return err
				}

				testCertificate.Spec.DNSNames = append(testCertificate.Spec.DNSNames, newDNSName)
				err = f.CRClient.Update(context.Background(), testCertificate)
				if err != nil {
					return err
				}
				return nil
			})

			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate Ready condition to be updated")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Sanity-check the issued Certificate")
			err = f.Helper().ValidateCertificate(testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN)

		s.it(f, "should issue a certificate that defines a wildcard DNS Name and its apex DNS Name", func(issuerRef cmmeta.ObjectReference) {
			dnsDomain := e2eutil.RandomSubdomain(s.DomainSuffix)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{"*." + dnsDomain, dnsDomain},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			// use a longer timeout for this, as it requires performing 2 dns validations in serial
			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testCertificate, time.Minute*10)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.WildcardsFeature, featureset.OnlySAN)
	})
}
