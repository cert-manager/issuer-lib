package signer

import (
	"crypto/x509"

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

func (c *certificateRequestImpl) GetRequest() (*x509.Certificate, []byte, error) {
	template, err := pki.GenerateTemplateFromCertificateRequest(c.CertificateRequest)
	if err != nil {
		return nil, nil, err
	}

	return template, c.Spec.Request, nil
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

func (c *certificateSigningRequestImpl) GetRequest() (*x509.Certificate, []byte, error) {
	template, err := pki.GenerateTemplateFromCertificateSigningRequest(c.CertificateSigningRequest)
	if err != nil {
		return nil, nil, err
	}

	return template, c.Spec.Request, nil
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
