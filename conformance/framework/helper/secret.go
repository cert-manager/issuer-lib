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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"conformance/framework/log"
)

// WaitForSecretCertificateData waits for the certificate data to be ready
// inside a Secret created by cert-manager.
func (h *Helper) WaitForSecretCertificateData(pollCtx context.Context, name string, namespace string, timeout time.Duration) (*corev1.Secret, error) {
	var secret *corev1.Secret
	logf, done := log.LogBackoff()
	defer done()

	err := wait.PollUntilContextTimeout(pollCtx, 500*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		secret, err = h.KubeClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error getting Secret %s: %w", name, err)
		}

		if len(secret.Data[corev1.TLSCertKey]) == 0 {
			logf("Secret still does not contain certificate data %s/%s", secret.Namespace, secret.Name)
			return false, nil
		}

		return true, nil
	})

	if err != nil {
		return secret, err
	}

	return secret, nil
}
