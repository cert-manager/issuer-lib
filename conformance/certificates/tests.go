/*
Copyright 2021 The cert-manager Authors.

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

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"conformance/framework"
	"conformance/framework/helper/featureset"
	"conformance/framework/helper/validation"
	"conformance/framework/helper/validation/certificates"
	e2eutil "conformance/util"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Define defines simple conformance tests that can be run against any issuer type.
// If Complete has not been called on this Suite before Define, it will be
// automatically called.
func (s *Suite) Define() {
	Describe("with issuer type "+s.Name, func() {
		f := framework.NewFramework(
			"certificates",
			s.KubeClientConfig,
			s.Namespace,
			[]client.Object{
				&cmapi.Certificate{},
				&cmapi.CertificateRequest{},
				&corev1.Secret{},
			},
		)

		sharedIPAddress := "127.0.0.1"

		// Wrap this in a BeforeEach else flags will not have been parsed and
		// f.Config will not be populated at the time that this code is run.
		BeforeEach(func() {
			if s.completed {
				return
			}
			s.complete(f)
		})

		type testCase struct {
			name          string // ginkgo v2 does not support using map[string] to store the test names (#5345)
			certModifiers []gen.CertificateModifier
			// The list of features that are required by the Issuer for the test to
			// run.
			requiredFeatures []featureset.Feature
			// Extra validations which may be needed for testing, on a test case by
			// case basis. All default validations will be run on every test.
			extraValidations []certificates.ValidationFunc
		}

		tests := []testCase{
			{
				name: "should issue an RSA certificate for a single distinct DNS Name",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN},
			},
			{
				name: "should issue an ECDSA certificate for a single distinct DNS Name",
				certModifiers: []gen.CertificateModifier{
					func(c *cmapi.Certificate) {
						c.Spec.PrivateKey = &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.ECDSAKeyAlgorithm,
						}
					},
					gen.SetCertificateDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				requiredFeatures: []featureset.Feature{featureset.ECDSAFeature, featureset.OnlySAN},
			},
			{
				name: "should issue an Ed25519 certificate for a single distinct DNS Name",
				certModifiers: []gen.CertificateModifier{
					func(c *cmapi.Certificate) {
						c.Spec.PrivateKey = &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.Ed25519KeyAlgorithm,
						}
					},
					gen.SetCertificateDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				requiredFeatures: []featureset.Feature{featureset.Ed25519FeatureSet, featureset.OnlySAN},
			},
			{
				name: "should issue an RSA certificate for a single Common Name",
				certModifiers: []gen.CertificateModifier{
					// Some issuers use the CN to define the cert's "ID"
					// if one cert manages to be in an error state in the issuer it might throw an error
					// this makes the CN more unique
					gen.SetCertificateCommonName("test-common-name-" + e2eutil.RandStringRunes(10)),
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature},
			},
			{
				name: "should issue an ECDSA certificate for a single Common Name",
				certModifiers: []gen.CertificateModifier{
					func(c *cmapi.Certificate) {
						c.Spec.PrivateKey = &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.ECDSAKeyAlgorithm,
						}
					},
					// Some issuers use the CN to define the cert's "ID"
					// if one cert manages to be in an error state in the issuer it might throw an error
					// this makes the CN more unique
					gen.SetCertificateCommonName("test-common-name-" + e2eutil.RandStringRunes(10)),
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.ECDSAFeature},
			},
			{
				name: "should issue an Ed25519 certificate for a single Common Name",
				certModifiers: []gen.CertificateModifier{
					func(c *cmapi.Certificate) {
						c.Spec.PrivateKey = &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.Ed25519KeyAlgorithm,
						}
					},
					// Some issuers use the CN to define the cert's "ID"
					// if one cert manages to be in an error state in the issuer it might throw an error
					// this makes the CN more unique
					gen.SetCertificateCommonName("test-common-name-" + e2eutil.RandStringRunes(10)),
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.Ed25519FeatureSet},
			},
			{
				name: "should issue a certificate that defines a Common Name and IP Address",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateIPs(sharedIPAddress),
					// Some issuers use the CN to define the cert's "ID"
					// if one cert manages to be in an error state in the issuer it might throw an error
					// this makes the CN more unique
					gen.SetCertificateCommonName("test-common-name-" + e2eutil.RandStringRunes(10)),
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.IPAddressFeature},
			},
			{
				name: "should issue a certificate that defines an IP Address",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateIPs(sharedIPAddress),
				},
				requiredFeatures: []featureset.Feature{featureset.IPAddressFeature},
			},
			{
				name: "should issue a certificate that defines a DNS Name and IP Address",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateIPs(sharedIPAddress),
					gen.SetCertificateDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.IPAddressFeature},
			},
			{
				name: "should issue a CA certificate with the CA basicConstraint set",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateIsCA(true),
					gen.SetCertificateDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				requiredFeatures: []featureset.Feature{featureset.IssueCAFeature},
			},
			{
				name: "should issue a certificate that defines an Email Address",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateEmails("alice@example.com"),
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.EmailSANsFeature},
			},
			{
				name: "should issue a certificate that defines a Common Name and URI SAN",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateURIs("spiffe://cluster.local/ns/sandbox/sa/foo"),
					// Some issuers use the CN to define the cert's "ID"
					// if one cert manages to be in an error state in the issuer it might throw an error
					// this makes the CN more unique
					gen.SetCertificateCommonName("test-common-name-" + e2eutil.RandStringRunes(10)),
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature, featureset.URISANsFeature},
			},
			{
				name: "should issue a certificate that defines a 2 distinct DNS Names with one copied to the Common Name",
				certModifiers: func() []gen.CertificateModifier {
					commonName := e2eutil.RandomSubdomain(s.DomainSuffix)

					return []gen.CertificateModifier{
						gen.SetCertificateCommonName(commonName),
						gen.SetCertificateDNSNames(commonName, e2eutil.RandomSubdomain(s.DomainSuffix)),
					}
				}(),
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature},
			},
			{
				name: "should issue a certificate that defines a distinct DNS Name and another distinct Common Name",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateCommonName(e2eutil.RandomSubdomain(s.DomainSuffix)),
					gen.SetCertificateDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				requiredFeatures: []featureset.Feature{featureset.CommonNameFeature},
			},
			{
				name: "should issue a certificate that defines a Common Name, DNS Name, and sets a duration",
				certModifiers: func() []gen.CertificateModifier {
					commonName := e2eutil.RandomSubdomain(s.DomainSuffix)

					return []gen.CertificateModifier{
						gen.SetCertificateCommonName(commonName),
						gen.SetCertificateDNSNames(commonName),
						gen.SetCertificateDuration(time.Hour * 896),
					}
				}(),
				requiredFeatures: []featureset.Feature{featureset.DurationFeature},
			},
			{
				name: "should issue a certificate that defines a DNS Name and sets a duration",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
					gen.SetCertificateDuration(time.Hour * 896),
				},
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.DurationFeature},
			},
			{
				name: "should issue a certificate which has a wildcard DNS Name defined",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateDNSNames("*." + e2eutil.RandomSubdomain(s.DomainSuffix)),
				},
				requiredFeatures: []featureset.Feature{featureset.WildcardsFeature, featureset.OnlySAN},
			},
			{
				name: "should issue a certificate which has a wildcard DNS Name and its apex DNS Name defined",
				certModifiers: func() []gen.CertificateModifier {
					dnsDomain := e2eutil.RandomSubdomain(s.DomainSuffix)

					return []gen.CertificateModifier{
						gen.SetCertificateDNSNames("*."+dnsDomain, dnsDomain),
					}
				}(),
				requiredFeatures: []featureset.Feature{featureset.WildcardsFeature, featureset.OnlySAN},
			},
			{
				name: "should issue a certificate that includes only a URISANs name",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateURIs("spiffe://cluster.local/ns/sandbox/sa/foo"),
				},
				requiredFeatures: []featureset.Feature{featureset.URISANsFeature, featureset.OnlySAN},
			},
			{
				name: "should issue a certificate that includes arbitrary key usages with common name",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateCommonName(e2eutil.RandomSubdomain(s.DomainSuffix)),
					gen.SetCertificateKeyUsages(
						cmapi.UsageServerAuth,
						cmapi.UsageClientAuth,
						cmapi.UsageDigitalSignature,
						cmapi.UsageDataEncipherment,
					),
				},
				extraValidations: []certificates.ValidationFunc{
					certificates.ExpectKeyUsageExtKeyUsageClientAuth,
					certificates.ExpectKeyUsageExtKeyUsageServerAuth,
					certificates.ExpectKeyUsageUsageDigitalSignature,
					certificates.ExpectKeyUsageUsageDataEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.KeyUsagesFeature},
			},
			{
				name: "should issue a certificate that includes arbitrary key usages with SAN only",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateDNSNames(e2eutil.RandomSubdomain(s.DomainSuffix)),
					gen.SetCertificateKeyUsages(
						cmapi.UsageSigning,
						cmapi.UsageDataEncipherment,
						cmapi.UsageServerAuth,
						cmapi.UsageClientAuth,
					),
				},
				extraValidations: []certificates.ValidationFunc{
					certificates.ExpectKeyUsageExtKeyUsageClientAuth,
					certificates.ExpectKeyUsageExtKeyUsageServerAuth,
					certificates.ExpectKeyUsageUsageDigitalSignature,
					certificates.ExpectKeyUsageUsageDataEncipherment,
				},
				requiredFeatures: []featureset.Feature{featureset.KeyUsagesFeature, featureset.OnlySAN},
			},
			{
				name: "should issue a signing CA certificate that has a large duration",
				certModifiers: []gen.CertificateModifier{
					gen.SetCertificateCommonName("cert-manager-ca"),
					gen.SetCertificateDuration(10000 * time.Hour),
					gen.SetCertificateIsCA(true),
				},
				requiredFeatures: []featureset.Feature{featureset.KeyUsagesFeature, featureset.DurationFeature, featureset.CommonNameFeature},
			},
			{
				name: "should issue a certificate that defines a long domain",
				certModifiers: func() []gen.CertificateModifier {
					const maxLengthOfDomainSegment = 63
					return []gen.CertificateModifier{
						gen.SetCertificateDNSNames(e2eutil.RandomSubdomainLength(s.DomainSuffix, maxLengthOfDomainSegment)),
					}
				}(),
				requiredFeatures: []featureset.Feature{featureset.OnlySAN, featureset.LongDomainFeatureSet},
			},
			{
				name: "should issue a basic, defaulted certificate for a single distinct DNS Name with a literal subject",
				certModifiers: func() []gen.CertificateModifier {
					host := fmt.Sprintf("*.%s.foo-long.bar.com", e2eutil.RandStringRunes(10))
					literalSubject := fmt.Sprintf("CN=%s,OU=FooLong,OU=Bar,OU=Baz,OU=Dept.,O=Corp.", host)

					return []gen.CertificateModifier{
						func(c *cmapi.Certificate) {
							c.Spec.LiteralSubject = literalSubject
						},
						gen.SetCertificateDNSNames(host),
					}
				}(),
				extraValidations: []certificates.ValidationFunc{
					func(certificate *cmapi.Certificate, secret *corev1.Secret) error {
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

						rdnSeq, err2 := pki.UnmarshalSubjectStringToRDNSequence(certificate.Spec.LiteralSubject)

						if err2 != nil {
							return err2
						}

						fmt.Fprintln(GinkgoWriter, "cert", base64.StdEncoding.EncodeToString(createdCert.RawSubject), dns, err, rest)
						if !reflect.DeepEqual(rdnSeq, dns) {
							return fmt.Errorf("generated certificate's subject [%s] does not match expected subject [%s]", dns.String(), certificate.Spec.LiteralSubject)
						}
						return nil
					},
				},
				requiredFeatures: []featureset.Feature{featureset.LiteralSubjectFeature},
			},
		}

		defineTest := func(test testCase) {
			s.it(f, test.name, func(ctx context.Context, issuerRef cmmeta.ObjectReference) {
				randomTestID := e2eutil.RandStringRunes(10)
				certificate := &cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "e2e-conformance-" + randomTestID,
						Namespace: f.Namespace,
						Labels: map[string]string{
							f.CleanupLabel: "true",
						},
						Annotations: map[string]string{
							"conformance.cert-manager.io/test-name": s.Name + " " + test.name,
						},
					},
					Spec: cmapi.CertificateSpec{
						SecretName: "e2e-conformance-tls-" + randomTestID,
						IssuerRef:  issuerRef,
						SecretTemplate: &cmapi.CertificateSecretTemplate{
							Labels: map[string]string{
								f.CleanupLabel: "true",
							},
						},
					},
				}

				certificate = gen.CertificateFrom(
					certificate,
					test.certModifiers...,
				)

				By("Creating a Certificate")
				err := f.CRClient.Create(ctx, certificate)
				Expect(err).NotTo(HaveOccurred())

				By("Waiting for the Certificate to be issued...")
				certificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, certificate.Name, certificate.Namespace, certificate.Generation, time.Minute*8)
				Expect(err).NotTo(HaveOccurred())

				By("Validating the issued Certificate...")
				validations := append(test.extraValidations, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
				err = f.Helper().ValidateCertificate(ctx, certificate, validations...)
				Expect(err).NotTo(HaveOccurred())
			}, test.requiredFeatures...)
		}

		for _, tc := range tests {
			defineTest(tc)
		}

		s.it(f, "should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted", func(ctx context.Context, issuerRef cmmeta.ObjectReference) {
			randomTestID := e2eutil.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "e2e-conformance-" + randomTestID,
					Namespace: f.Namespace,
					Labels: map[string]string{
						f.CleanupLabel: "true",
					},
					Annotations: map[string]string{
						"conformance.cert-manager.io/test-name": s.Name + " should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted",
					},
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "e2e-conformance-tls-" + randomTestID,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:  issuerRef,
					SecretTemplate: &cmapi.CertificateSecretTemplate{
						Labels: map[string]string{
							f.CleanupLabel: "true",
						},
					},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate.Name, testCertificate.Namespace, testCertificate.Generation, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(ctx, testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())

			By("Deleting existing certificate data in Secret")
			sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace).
				Get(ctx, testCertificate.Spec.SecretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get secret containing signed certificate key pair data")

			sec = sec.DeepCopy()
			crtPEM1 := sec.Data[corev1.TLSCertKey]
			crt1, err := pki.DecodeX509CertificateBytes(crtPEM1)
			Expect(err).NotTo(HaveOccurred(), "failed to get decode first signed certificate data")

			sec.Data[corev1.TLSCertKey] = []byte{}

			_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace).Update(ctx, sec, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to update secret by deleting the signed certificate data")

			By("Waiting for the Certificate to re-issue a certificate")
			sec, err = f.Helper().WaitForSecretCertificateData(ctx, sec.Name, f.Namespace, time.Minute*8)
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

		s.it(f, "should allow updating an existing certificate with a new DNS Name", func(ctx context.Context, issuerRef cmmeta.ObjectReference) {
			randomTestID := e2eutil.RandStringRunes(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "e2e-conformance-" + randomTestID,
					Namespace: f.Namespace,
					Labels: map[string]string{
						f.CleanupLabel: "true",
					},
					Annotations: map[string]string{
						"conformance.cert-manager.io/test-name": s.Name + " should allow updating an existing certificate with a new DNS Name",
					},
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "e2e-conformance-tls-" + randomTestID,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:  issuerRef,
					SecretTemplate: &cmapi.CertificateSecretTemplate{
						Labels: map[string]string{
							f.CleanupLabel: "true",
						},
					},
				},
			}
			validations := validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be ready")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate.Name, testCertificate.Namespace, testCertificate.Generation, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Sanity-check the issued Certificate")
			err = f.Helper().ValidateCertificate(ctx, testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())

			By("Updating the Certificate after having added an additional dnsName")
			newDNSName := e2eutil.RandomSubdomain(s.DomainSuffix)
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				err := f.CRClient.Get(context.Background(), types.NamespacedName{Name: testCertificate.Name, Namespace: testCertificate.Namespace}, testCertificate)
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
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate.Name, testCertificate.Namespace, testCertificate.Generation, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Sanity-check the issued Certificate")
			err = f.Helper().ValidateCertificate(ctx, testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN)
	})
}
