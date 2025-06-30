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
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
)

func TestSetIssuerStatusCondition(t *testing.T) {
	type testCase struct {
		name string

		existingConditions []metav1.Condition
		patchConditions    []metav1.Condition
		conditionType      string
		status             metav1.ConditionStatus

		expectedCondition metav1.Condition
		expectNewEntry    bool
	}

	fakeTime1 := randomTime()
	fakeTimeObj1 := metav1.NewTime(fakeTime1)

	fakeTime2 := randomTime()
	fakeTimeObj2 := metav1.NewTime(fakeTime2)
	fakeClock2 := clocktesting.NewFakeClock(fakeTime2)

	testCases := []testCase{
		{
			name: "if the condition does NOT change its status, the last transition time should not be updated",
			existingConditions: []metav1.Condition{
				{
					Type:   v1alpha1.IssuerConditionTypeReady,
					Status: metav1.ConditionTrue,
				},
			},
			patchConditions: []metav1.Condition{},
			conditionType:   v1alpha1.IssuerConditionTypeReady,
			status:          metav1.ConditionTrue,

			expectedCondition: metav1.Condition{
				Type:               v1alpha1.IssuerConditionTypeReady,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: fakeTimeObj1,
			},
			expectNewEntry: true,
		},
		{
			name: "if the condition DOES change its status, the last transition time should be updated",
			existingConditions: []metav1.Condition{
				{
					Type:   v1alpha1.IssuerConditionTypeReady,
					Status: metav1.ConditionTrue,
				},
			},
			patchConditions: []metav1.Condition{},
			conditionType:   v1alpha1.IssuerConditionTypeReady,
			status:          metav1.ConditionFalse,

			expectedCondition: metav1.Condition{
				Type:               v1alpha1.IssuerConditionTypeReady,
				Status:             metav1.ConditionFalse,
				LastTransitionTime: fakeTimeObj2,
			},
			expectNewEntry: true,
		},
		{
			name: "if the patch contains already contains the condition, it should get overwritten",
			existingConditions: []metav1.Condition{
				{
					Type:   v1alpha1.IssuerConditionTypeReady,
					Status: metav1.ConditionTrue,
				},
			},
			patchConditions: []metav1.Condition{
				{
					Type:   v1alpha1.IssuerConditionTypeReady,
					Status: metav1.ConditionTrue,
				},
			},
			conditionType: v1alpha1.IssuerConditionTypeReady,
			status:        metav1.ConditionTrue,

			expectedCondition: metav1.Condition{
				Type:               v1alpha1.IssuerConditionTypeReady,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: fakeTimeObj1,
			},
			expectNewEntry: false,
		},
		{
			name: "if the patch contains another condition type, it should get added",
			existingConditions: []metav1.Condition{
				{
					Type:   v1alpha1.IssuerConditionTypeReady,
					Status: metav1.ConditionTrue,
				},
			},
			patchConditions: []metav1.Condition{
				{
					Type:   v1alpha1.IssuerConditionTypeReady,
					Status: metav1.ConditionTrue,
				},
			},
			conditionType: "AnotherCondition",
			status:        metav1.ConditionTrue,

			expectedCondition: metav1.Condition{
				Type:               "AnotherCondition",
				Status:             metav1.ConditionTrue,
				LastTransitionTime: fakeTimeObj2,
			},
			expectNewEntry: true,
		},
	}

	defaultConditions := func(t *testing.T, conditions []metav1.Condition) []metav1.Condition {
		t.Helper()

		for i := range conditions {
			if !conditions[i].LastTransitionTime.IsZero() ||
				conditions[i].Reason != "" ||
				conditions[i].Message != "" ||
				conditions[i].ObservedGeneration != 0 {
				t.Fatal("this field is managed by the test and should not be set")
			}
			conditions[i].LastTransitionTime = fakeTimeObj1
			conditions[i].Reason = "OldReason"
			conditions[i].Message = "OldMessage"
			conditions[i].ObservedGeneration = 7
		}

		return conditions
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			test.existingConditions = defaultConditions(t, test.existingConditions)
			test.patchConditions = defaultConditions(t, test.patchConditions)

			patchConditions := append([]metav1.Condition{}, test.patchConditions...)

			cond, time := SetIssuerStatusCondition(
				fakeClock2,
				test.existingConditions,
				&patchConditions,
				8,
				test.conditionType,
				test.status,
				"NewReason",
				"NewMessage",
			)

			if test.expectedCondition.Reason != "" ||
				test.expectedCondition.Message != "" ||
				test.expectedCondition.ObservedGeneration != 0 {
				t.Fatal("this field is managed by the test and should not be set")
			}
			test.expectedCondition.Reason = "NewReason"
			test.expectedCondition.Message = "NewMessage"
			test.expectedCondition.ObservedGeneration = 8
			require.Equal(t, test.expectedCondition, *cond)
			require.Equal(t, fakeTimeObj2, time)

			// Check that the patchConditions slice got a new entry if expected
			if test.expectNewEntry {
				require.Equal(t, len(test.patchConditions)+1, len(patchConditions))
			} else {
				require.Equal(t, len(test.patchConditions), len(patchConditions))
			}

			// Make sure only the expected condition in the patchConditions slice got updated
			for _, c := range patchConditions {
				if c.Type == test.conditionType {
					require.Equal(t, test.expectedCondition, c)
					continue
				}

				for _, ec := range test.patchConditions {
					if ec.Type == c.Type {
						require.Equal(t, ec, c)
					}
				}
			}
		})
	}
}
