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

package helper

import (
	"context"
	"fmt"
	"time"

	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"conformance/framework/log"
)

// WaitForCertificateSigningRequestSigned waits for the
// CertificateSigningRequest resource to be signed.
func (h *Helper) WaitForCertificateSigningRequestSigned(pollCtx context.Context, name string, timeout time.Duration) (*certificatesv1.CertificateSigningRequest, error) {
	var csr *certificatesv1.CertificateSigningRequest
	logf, done := log.LogBackoff()
	defer done()

	err := wait.PollUntilContextTimeout(pollCtx, 500*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		csr, err = h.KubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error getting CertificateSigningRequest %s: %w", name, err)
		}

		if util.CertificateSigningRequestIsFailed(csr) {
			return false, fmt.Errorf("CertificateSigningRequest has failed: %v", csr.Status)
		}

		if len(csr.Status.Certificate) == 0 {
			logf("CertificateSigningRequest is not yet signed %s", csr.Name)
			return false, nil
		}

		return true, nil
	})

	if err != nil {
		return csr, err
	}

	return csr, nil
}
