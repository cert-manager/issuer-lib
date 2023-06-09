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

package helper

import (
	"context"
	"fmt"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/issuer-lib/conformance/framework/log"
)

func (h *Helper) waitForCertificateCondition(pollCtx context.Context, client clientset.CertificateInterface, name string, check func(*v1.Certificate) bool, timeout time.Duration) (*v1.Certificate, error) {
	var certificate *v1.Certificate
	pollErr := wait.PollUntilContextTimeout(pollCtx, 500*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		certificate, err = client.Get(ctx, name, metav1.GetOptions{})
		if nil != err {
			certificate = nil
			return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
		}

		return check(certificate), nil
	})

	return certificate, pollErr
}

// WaitForCertificateReadyAndDoneIssuing waits for the certificate resource to be in a Ready=True state and not be in an Issuing state.
// The Ready=True condition will be checked against the provided certificate to make sure that it is up-to-date (condition gen. >= cert gen.).
func (h *Helper) WaitForCertificateReadyAndDoneIssuing(ctx context.Context, cert *v1.Certificate, timeout time.Duration) (*v1.Certificate, error) {
	ready_true_condition := v1.CertificateCondition{
		Type:               v1.CertificateConditionReady,
		Status:             cmmeta.ConditionTrue,
		ObservedGeneration: cert.Generation,
	}
	issuing_true_condition := v1.CertificateCondition{
		Type:   v1.CertificateConditionIssuing,
		Status: cmmeta.ConditionTrue,
	}
	logf, done := log.LogBackoff()
	defer done()
	return h.waitForCertificateCondition(ctx, h.CMClient.CertmanagerV1().Certificates(cert.Namespace), cert.Name, func(certificate *v1.Certificate) bool {
		if !apiutil.CertificateHasConditionWithObservedGeneration(certificate, ready_true_condition) {
			logf(
				"Expected Certificate %v condition %v=%v (generation >= %v) but it has: %v",
				certificate.Name,
				ready_true_condition.Type,
				ready_true_condition.Status,
				ready_true_condition.ObservedGeneration,
				certificate.Status.Conditions,
			)
			return false
		}

		if apiutil.CertificateHasCondition(certificate, issuing_true_condition) {
			logf("Expected Certificate %v condition %v to be missing but it has: %v", certificate.Name, issuing_true_condition.Type, certificate.Status.Conditions)
			return false
		}

		if certificate.Status.NextPrivateKeySecretName != nil {
			logf("Expected Certificate %v 'next-private-key-secret-name' attribute to be empty but has: %v", certificate.Name, *certificate.Status.NextPrivateKeySecretName)
			return false
		}

		return true
	}, timeout)
}
