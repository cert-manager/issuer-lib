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
	"math/rand"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"
)

// We are using a random time generator to generate random times for the
// fakeClock. This will result in different times for each test run and
// should make sure we don't incorrectly rely on `time.Now()` in the code.
// WARNING: This approach does not guarantee that incorrect use of `time.Now()`
// is always detected, but after a few test runs it should be very unlikely.
func randomTime() time.Time {
	minTime := time.Date(1970, 1, 0, 0, 0, 0, 0, time.UTC).Unix()
	maxTime := time.Date(2070, 1, 0, 0, 0, 0, 0, time.UTC).Unix()
	delta := maxTime - minTime

	sec := rand.Int63n(delta) + minTime // #nosec: G404 -- The random time does not have to be secure.
	return time.Unix(sec, 0)
}

func TestSetCertificateRequestStatusCondition(t *testing.T) {
	type testCase struct {
		name string

		existingConditions []cmapi.CertificateRequestCondition
		patchConditions    []cmapi.CertificateRequestCondition
		conditionType      cmapi.CertificateRequestConditionType
		status             cmmeta.ConditionStatus

		expectedCondition cmapi.CertificateRequestCondition
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
			existingConditions: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
				},
			},
			patchConditions: []cmapi.CertificateRequestCondition{},
			conditionType:   cmapi.CertificateRequestConditionReady,
			status:          cmmeta.ConditionTrue,

			expectedCondition: cmapi.CertificateRequestCondition{
				Type:               cmapi.CertificateRequestConditionReady,
				Status:             cmmeta.ConditionTrue,
				LastTransitionTime: &fakeTimeObj1,
			},
			expectNewEntry: true,
		},
		{
			name: "if the condition DOES change its status, the last transition time should be updated",
			existingConditions: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
				},
			},
			patchConditions: []cmapi.CertificateRequestCondition{},
			conditionType:   cmapi.CertificateRequestConditionReady,
			status:          cmmeta.ConditionFalse,

			expectedCondition: cmapi.CertificateRequestCondition{
				Type:               cmapi.CertificateRequestConditionReady,
				Status:             cmmeta.ConditionFalse,
				LastTransitionTime: &fakeTimeObj2,
			},
			expectNewEntry: true,
		},
		{
			name: "if the patch contains already contains the condition, it should get overwritten",
			existingConditions: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
				},
			},
			patchConditions: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
				},
			},
			conditionType: cmapi.CertificateRequestConditionReady,
			status:        cmmeta.ConditionTrue,

			expectedCondition: cmapi.CertificateRequestCondition{
				Type:               cmapi.CertificateRequestConditionReady,
				Status:             cmmeta.ConditionTrue,
				LastTransitionTime: &fakeTimeObj1,
			},
			expectNewEntry: false,
		},
		{
			name: "if the patch contains another condition type, it should get added",
			existingConditions: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
				},
			},
			patchConditions: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
				},
			},
			conditionType: cmapi.CertificateRequestConditionApproved,
			status:        cmmeta.ConditionTrue,

			expectedCondition: cmapi.CertificateRequestCondition{
				Type:               cmapi.CertificateRequestConditionApproved,
				Status:             cmmeta.ConditionTrue,
				LastTransitionTime: &fakeTimeObj2,
			},
			expectNewEntry: true,
		},
	}

	defaultConditions := func(t *testing.T, conditions []cmapi.CertificateRequestCondition) []cmapi.CertificateRequestCondition {
		t.Helper()

		for i := range conditions {
			if conditions[i].LastTransitionTime != nil ||
				conditions[i].Reason != "" ||
				conditions[i].Message != "" {
				t.Fatal("this field is managed by the test and should not be set")
			}
			conditions[i].LastTransitionTime = &fakeTimeObj1
			conditions[i].Reason = "OldReason"
			conditions[i].Message = "OldMessage"
		}

		return conditions
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			test.existingConditions = defaultConditions(t, test.existingConditions)
			test.patchConditions = defaultConditions(t, test.patchConditions)

			patchConditions := append([]cmapi.CertificateRequestCondition{}, test.patchConditions...)

			cond, time := SetCertificateRequestStatusCondition(
				fakeClock2,
				test.existingConditions,
				&patchConditions,
				test.conditionType,
				test.status,
				"NewReason",
				"NewMessage",
			)

			if test.expectedCondition.Reason != "" ||
				test.expectedCondition.Message != "" {
				t.Fatal("this field is managed by the test and should not be set")
			}
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
