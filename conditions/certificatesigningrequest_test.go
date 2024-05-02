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
	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestSetCertificateSigningRequestStatusCondition(t *testing.T) {
	type testCase struct {
		name string

		existingConditions []certificatesv1.CertificateSigningRequestCondition
		patchConditions    []certificatesv1.CertificateSigningRequestCondition
		conditionType      certificatesv1.RequestConditionType
		status             v1.ConditionStatus

		expectedCondition certificatesv1.CertificateSigningRequestCondition
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
			existingConditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateApproved,
					Status: v1.ConditionTrue,
				},
			},
			patchConditions: []certificatesv1.CertificateSigningRequestCondition{},
			conditionType:   certificatesv1.CertificateApproved,
			status:          v1.ConditionTrue,

			expectedCondition: certificatesv1.CertificateSigningRequestCondition{
				Type:               certificatesv1.CertificateApproved,
				Status:             v1.ConditionTrue,
				LastTransitionTime: fakeTimeObj1,
			},
			expectNewEntry: true,
		},
		{
			name: "if the condition DOES change its status, the last transition time should be updated",
			existingConditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateApproved,
					Status: v1.ConditionTrue,
				},
			},
			patchConditions: []certificatesv1.CertificateSigningRequestCondition{},
			conditionType:   certificatesv1.CertificateApproved,
			status:          v1.ConditionFalse,

			expectedCondition: certificatesv1.CertificateSigningRequestCondition{
				Type:               certificatesv1.CertificateApproved,
				Status:             v1.ConditionFalse,
				LastTransitionTime: fakeTimeObj2,
			},
			expectNewEntry: true,
		},
		{
			name: "if the patch contains already contains the condition, it should get overwritten",
			existingConditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateApproved,
					Status: v1.ConditionTrue,
				},
			},
			patchConditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateApproved,
					Status: v1.ConditionTrue,
				},
			},
			conditionType: certificatesv1.CertificateApproved,
			status:        v1.ConditionTrue,

			expectedCondition: certificatesv1.CertificateSigningRequestCondition{
				Type:               certificatesv1.CertificateApproved,
				Status:             v1.ConditionTrue,
				LastTransitionTime: fakeTimeObj1,
			},
			expectNewEntry: false,
		},
		{
			name: "if the patch contains another condition type, it should get added",
			existingConditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateApproved,
					Status: v1.ConditionTrue,
				},
			},
			patchConditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateApproved,
					Status: v1.ConditionTrue,
				},
			},
			conditionType: certificatesv1.CertificateDenied,
			status:        v1.ConditionTrue,

			expectedCondition: certificatesv1.CertificateSigningRequestCondition{
				Type:               certificatesv1.CertificateDenied,
				Status:             v1.ConditionTrue,
				LastTransitionTime: fakeTimeObj2,
			},
			expectNewEntry: true,
		},
	}

	defaultConditions := func(t *testing.T, conditions []certificatesv1.CertificateSigningRequestCondition) []certificatesv1.CertificateSigningRequestCondition {
		t.Helper()

		for i := range conditions {
			if !conditions[i].LastUpdateTime.IsZero() ||
				!conditions[i].LastTransitionTime.IsZero() ||
				conditions[i].Reason != "" ||
				conditions[i].Message != "" {
				t.Fatal("this field is managed by the test and should not be set")
			}
			conditions[i].LastUpdateTime = fakeTimeObj1
			conditions[i].LastTransitionTime = fakeTimeObj1
			conditions[i].Reason = "OldReason"
			conditions[i].Message = "OldMessage"
		}

		return conditions
	}

	for _, test := range testCases {
		test := test

		t.Run(test.name, func(t *testing.T) {
			test.existingConditions = defaultConditions(t, test.existingConditions)
			test.patchConditions = defaultConditions(t, test.patchConditions)

			patchConditions := append([]certificatesv1.CertificateSigningRequestCondition{}, test.patchConditions...)

			cond, time := SetCertificateSigningRequestStatusCondition(
				fakeClock2,
				test.existingConditions,
				&patchConditions,
				test.conditionType,
				test.status,
				"NewReason",
				"NewMessage",
			)

			if !test.expectedCondition.LastUpdateTime.IsZero() ||
				test.expectedCondition.Reason != "" ||
				test.expectedCondition.Message != "" {
				t.Fatal("this field is managed by the test and should not be set")
			}
			test.expectedCondition.LastUpdateTime = fakeTimeObj2
			test.expectedCondition.Reason = "NewReason"
			test.expectedCondition.Message = "NewMessage"
			require.Equal(t, test.expectedCondition, *cond)
			require.Equal(t, &fakeTimeObj2, time)

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
