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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
)

// Update the status with the provided condition details & return
// the added condition.
func SetIssuerStatusCondition(
	clock clock.PassiveClock,
	existingConditions []metav1.Condition,
	patchConditions *[]metav1.Condition,
	observedGeneration int64,
	conditionType string,
	status metav1.ConditionStatus,
	reason, message string,
) (*metav1.Condition, metav1.Time) {
	newCondition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: observedGeneration,
	}

	nowTime := metav1.NewTime(clock.Now())
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

		return &newCondition, nowTime
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	*patchConditions = append(*patchConditions, newCondition)

	return &newCondition, nowTime
}

func GetIssuerStatusCondition(
	conditions []metav1.Condition,
	conditionType string,
) *metav1.Condition {
	for _, cond := range conditions {
		if cond.Type == conditionType {
			return &cond
		}
	}
	return nil
}
