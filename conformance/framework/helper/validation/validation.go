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

package validation

import (
	"github.com/cert-manager/issuer-lib/conformance/framework/helper/featureset"
	"github.com/cert-manager/issuer-lib/conformance/framework/helper/validation/certificates"
	"github.com/cert-manager/issuer-lib/conformance/framework/helper/validation/certificatesigningrequests"
)

func CertificateSetForUnsupportedFeatureSet(fs featureset.FeatureSet) []certificates.ValidationFunc {
	// basics
	out := []certificates.ValidationFunc{
		certificates.ExpectCertificateDNSNamesToMatch,
		certificates.ExpectCertificateOrganizationToMatch,
		certificates.ExpectValidCertificate,
		certificates.ExpectValidPrivateKeyData,
		certificates.ExpectValidCommonName,
		certificates.ExpectValidBasicConstraints,

		certificates.ExpectValidNotAfterDate,
		certificates.ExpectValidKeysInSecret,
		certificates.ExpectValidAnnotations,

		certificates.ExpectConditionReadyObservedGeneration,
	}

	if !fs.Contains(featureset.URISANsFeature) {
		out = append(out, certificates.ExpectCertificateURIsToMatch)
	}

	if !fs.Contains(featureset.EmailSANsFeature) {
		out = append(out, certificates.ExpectEmailsToMatch)
	}

	if !fs.Contains(featureset.IPAddressFeature) {
		out = append(out, certificates.ExpectCertificateIPsToMatch)
	}

	if !fs.Contains(featureset.SaveCAToSecret) {
		out = append(out, certificates.ExpectCorrectTrustChain)

		if !fs.Contains(featureset.SaveRootCAToSecret) {
			out = append(out, certificates.ExpectCARootCertificate)
		}
	}

	if !fs.Contains(featureset.DurationFeature) {
		out = append(out, certificates.ExpectDurationToMatch)
	}

	return out
}

func CertificateSigningRequestSetForUnsupportedFeatureSet(fs featureset.FeatureSet) []certificatesigningrequests.ValidationFunc {
	// basics
	out := []certificatesigningrequests.ValidationFunc{
		certificatesigningrequests.ExpectCertificateDNSNamesToMatch,
		certificatesigningrequests.ExpectCertificateOrganizationToMatch,
		certificatesigningrequests.ExpectValidCertificate,
		certificatesigningrequests.ExpectValidPrivateKeyData,
		certificatesigningrequests.ExpectValidCommonName,
		certificatesigningrequests.ExpectValidBasicConstraints,

		certificatesigningrequests.ExpectKeyUsageUsageDigitalSignature,

		certificatesigningrequests.ExpectConditionApproved,
		certificatesigningrequests.ExpectConditiotNotDenied,
		certificatesigningrequests.ExpectConditionNotFailed,
	}

	if !fs.Contains(featureset.URISANsFeature) {
		out = append(out, certificatesigningrequests.ExpectCertificateURIsToMatch)
	}

	if !fs.Contains(featureset.EmailSANsFeature) {
		out = append(out, certificatesigningrequests.ExpectEmailsToMatch)
	}

	if !fs.Contains(featureset.IPAddressFeature) {
		out = append(out, certificatesigningrequests.ExpectCertificateIPsToMatch)
	}

	if !fs.Contains(featureset.DurationFeature) {
		out = append(out, certificatesigningrequests.ExpectDurationToMatch)
	}

	return out
}
