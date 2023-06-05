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

package conditions

import (
	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
)

// Update the status with the provided condition details & return
// the added condition.
func SetCertificateSigningRequestStatusCondition(
	clock clock.PassiveClock,
	existingConditions []certificatesv1.CertificateSigningRequestCondition,
	patchConditions *[]certificatesv1.CertificateSigningRequestCondition,
	conditionType certificatesv1.RequestConditionType,
	status v1.ConditionStatus,
	reason, message string,
) (*certificatesv1.CertificateSigningRequestCondition, *metav1.Time) {
	newCondition := certificatesv1.CertificateSigningRequestCondition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	nowTime := metav1.NewTime(clock.Now())
	newCondition.LastUpdateTime = nowTime
	newCondition.LastTransitionTime = nowTime

	// Reset the LastTransitionTime if the status hasn't changed
	for _, cond := range existingConditions {
		if cond.Type != conditionType {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if cond.Status == status {
			newCondition.LastTransitionTime = cond.LastTransitionTime
		}
	}

	// Search through existing conditions
	for idx, cond := range *patchConditions {
		// Skip unrelated conditions
		if cond.Type != conditionType {
			continue
		}

		// Overwrite the existing condition
		(*patchConditions)[idx] = newCondition

		return &newCondition, &nowTime
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	*patchConditions = append(*patchConditions, newCondition)

	return &newCondition, &nowTime
}

func GetCertificateSigningRequestStatusCondition(
	conditions []certificatesv1.CertificateSigningRequestCondition,
	conditionType certificatesv1.RequestConditionType,
) *certificatesv1.CertificateSigningRequestCondition {
	for _, cond := range conditions {
		if cond.Type == conditionType {
			return &cond
		}
	}
	return nil
}
