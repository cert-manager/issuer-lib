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

package signer

import (
	"crypto/x509"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateRequestObject represents either a cert-manager CertificateRequest
// or a Kubernetes CertificateSigningRequest resource. The interface hides the
// underlying spec fields and exposes a certificate template and the raw CSR
// bytes. This lets the signer be agnostic to the underlying resource type and
// to how spec fields are interpreted (for example, defaulting logic). The
// signer can still access labels, annotations, or other metadata, and can use
// `GetConditions` to retrieve the resource's conditions.
type CertificateRequestObject interface {
	metav1.Object

	// Return the Certificate details originating from the cert-manager
	// CertificateRequest or Kubernetes CertificateSigningRequest resources.
	GetCertificateDetails() (details CertificateDetails, err error)

	GetConditions() []metav1.Condition
}

type CertificateDetails struct {
	CSR         []byte
	Duration    time.Duration
	IsCA        bool
	MaxPathLen  *int
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
}

// CertificateTemplate generates a certificate template for issuance,
// based on CertificateDetails extracted from the CertificateRequest or
// CertificateSigningRequest resource.
//
// This function internally calls CertificateTemplateFromCSRPEM, which performs
// additional work such as parsing the CSR and verifying signatures. Since this
// operation can be expensive, issuer implementations should call this function
// only when a certificate template is actually needed (e.g., not when proxying
// the X.509 CSR to a CA).
func (cd CertificateDetails) CertificateTemplate() (template *x509.Certificate, err error) {
	return pki.CertificateTemplateFromCSRPEM(
		cd.CSR,
		pki.CertificateTemplateOverrideDuration(cd.Duration),
		pki.CertificateTemplateValidateAndOverrideBasicConstraints(cd.IsCA, cd.MaxPathLen), // Override the basic constraints, but make sure they match the constraints in the CSR if present
		pki.CertificateTemplateValidateAndOverrideKeyUsages(cd.KeyUsage, cd.ExtKeyUsage),   // Override the key usages, but make sure they match the usages in the CSR if present
	)
}

type certificateRequestImpl struct {
	*cmapi.CertificateRequest
}

var _ CertificateRequestObject = &certificateRequestImpl{}

func CertificateRequestObjectFromCertificateRequest(cr *cmapi.CertificateRequest) CertificateRequestObject {
	return &certificateRequestImpl{cr}
}

func (c *certificateRequestImpl) GetCertificateDetails() (CertificateDetails, error) {
	duration := apiutil.DefaultCertDuration(c.Spec.Duration)

	keyUsage, extKeyUsage, err := pki.KeyUsagesForCertificateOrCertificateRequest(c.Spec.Usages, c.Spec.IsCA)
	if err != nil {
		return CertificateDetails{}, err
	}

	return CertificateDetails{
		CSR:         c.Spec.Request,
		Duration:    duration,
		IsCA:        c.Spec.IsCA,
		MaxPathLen:  nil,
		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage,
	}, nil
}

func (c *certificateRequestImpl) GetConditions() []metav1.Condition {
	conditions := make([]metav1.Condition, 0, len(c.Status.Conditions))
	for _, condition := range c.Status.Conditions {
		var lastTransition metav1.Time
		if lt := condition.LastTransitionTime; lt != nil {
			lastTransition = *lt
		}
		conditions = append(conditions, metav1.Condition{
			Type:               string(condition.Type),
			Status:             metav1.ConditionStatus(condition.Status),
			LastTransitionTime: lastTransition,
			Reason:             condition.Reason,
			Message:            condition.Message,
		})
	}
	return conditions
}

type certificateSigningRequestImpl struct {
	*certificatesv1.CertificateSigningRequest
}

var _ CertificateRequestObject = &certificateSigningRequestImpl{}

func CertificateRequestObjectFromCertificateSigningRequest(csr *certificatesv1.CertificateSigningRequest) CertificateRequestObject {
	return &certificateSigningRequestImpl{csr}
}

func (c *certificateSigningRequestImpl) GetCertificateDetails() (CertificateDetails, error) {
	duration, err := pki.DurationFromCertificateSigningRequest(c.CertificateSigningRequest)
	if err != nil {
		return CertificateDetails{}, err
	}

	isCA := c.CertificateSigningRequest.Annotations[experimentalapi.CertificateSigningRequestIsCAAnnotationKey] == "true"

	keyUsage, extKeyUsage, err := pki.BuildKeyUsagesKube(c.Spec.Usages)
	if err != nil {
		return CertificateDetails{}, err
	}

	return CertificateDetails{
		CSR:         c.Spec.Request,
		Duration:    duration,
		IsCA:        isCA,
		MaxPathLen:  nil,
		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage,
	}, nil
}

func (c *certificateSigningRequestImpl) GetConditions() []metav1.Condition {
	conditions := make([]metav1.Condition, 0, len(c.Status.Conditions))
	for _, condition := range c.Status.Conditions {
		conditions = append(conditions, metav1.Condition{
			Type:               string(condition.Type),
			Status:             metav1.ConditionStatus(condition.Status),
			LastTransitionTime: condition.LastTransitionTime,
			Reason:             condition.Reason,
			Message:            condition.Message,
		})
	}
	return conditions
}
