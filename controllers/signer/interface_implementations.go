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
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	certificatesv1 "k8s.io/api/certificates/v1"
)

type certificateRequestImpl struct {
	*cmapi.CertificateRequest
}

var _ CertificateRequestObject = &certificateRequestImpl{}

func CertificateRequestObjectFromCertificateRequest(cr *cmapi.CertificateRequest) CertificateRequestObject {
	return &certificateRequestImpl{cr}
}

func (c *certificateRequestImpl) GetRequest() (*x509.Certificate, time.Duration, []byte, error) {
	duration := apiutil.DefaultCertDuration(c.CertificateRequest.Spec.Duration)

	template, err := pki.CertificateTemplateFromCertificateRequest(c.CertificateRequest)
	if err != nil {
		return nil, 0, nil, err
	}

	return template, duration, c.Spec.Request, nil
}

func (c *certificateRequestImpl) GetConditions() []cmapi.CertificateRequestCondition {
	return c.Status.Conditions
}

type certificateSigningRequestImpl struct {
	*certificatesv1.CertificateSigningRequest
}

var _ CertificateRequestObject = &certificateSigningRequestImpl{}

func CertificateRequestObjectFromCertificateSigningRequest(csr *certificatesv1.CertificateSigningRequest) CertificateRequestObject {
	return &certificateSigningRequestImpl{csr}
}

func (c *certificateSigningRequestImpl) GetRequest() (*x509.Certificate, time.Duration, []byte, error) {
	duration, err := pki.DurationFromCertificateSigningRequest(c.CertificateSigningRequest)
	if err != nil {
		return nil, 0, nil, err
	}

	template, err := pki.CertificateTemplateFromCertificateSigningRequest(c.CertificateSigningRequest)
	if err != nil {
		return nil, 0, nil, err
	}

	return template, duration, c.Spec.Request, nil
}

func (c *certificateSigningRequestImpl) GetConditions() []cmapi.CertificateRequestCondition {
	conditions := make([]cmapi.CertificateRequestCondition, 0, len(c.Status.Conditions))
	for _, condition := range c.Status.Conditions {
		lastTransition := condition.LastTransitionTime
		conditions = append(conditions, cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionType(condition.Type),
			Status:             cmmeta.ConditionStatus(condition.Status),
			LastTransitionTime: &lastTransition,
			Reason:             condition.Reason,
			Message:            condition.Message,
		})
	}
	return conditions
}
