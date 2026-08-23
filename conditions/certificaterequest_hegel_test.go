/*
Copyright 2026 The cert-manager Authors.

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
	"reflect"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"

	"hegel.dev/go/hegel"
)

func drawCertificateRequestConditionSet(ht *hegel.T, statuses []cmmeta.ConditionStatus) []cmapi.CertificateRequestCondition {
	conditions := []cmapi.CertificateRequestCondition{}
	for _, conditionType := range conditionTypePool {
		if !hegel.Draw(ht, hegel.Booleans()) {
			continue
		}
		lastTransitionTime := metav1.NewTime(drawTime(ht))
		conditions = append(conditions, cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionType(conditionType),
			Status:             statuses[hegel.Draw(ht, hegel.Integers(0, int64(len(statuses)-1)))],
			Reason:             hegel.Draw(ht, hegel.Text().MaxSize(10)),
			Message:            hegel.Draw(ht, hegel.Text().MaxSize(10)),
			LastTransitionTime: &lastTransitionTime,
		})
	}
	return conditions
}

// TestSetCertificateRequestStatusConditionProperty: the same set-or-overwrite
// rule as SetIssuerStatusCondition, for CertificateRequest conditions: the
// returned condition carries the requested type, status, reason and message;
// LastTransitionTime is preserved from the existing condition of the same
// type iff its status already matched, and is the clock's now otherwise; the
// patch slice gets the condition overwritten in place or appended, all other
// entries untouched. Replaces the four-example
// TestSetCertificateRequestStatusCondition table.
func TestSetCertificateRequestStatusConditionProperty(t *testing.T) {
	statuses := []cmmeta.ConditionStatus{cmmeta.ConditionTrue, cmmeta.ConditionFalse, cmmeta.ConditionUnknown}

	hegel.Test(t, func(ht *hegel.T) {
		now := drawTime(ht)
		nowObj := metav1.NewTime(now)

		existingConditions := drawCertificateRequestConditionSet(ht, statuses)
		patchConditions := drawCertificateRequestConditionSet(ht, statuses)

		conditionType := cmapi.CertificateRequestConditionType(conditionTypePool[hegel.Draw(ht, hegel.Integers(0, int64(len(conditionTypePool)-1)))])
		status := statuses[hegel.Draw(ht, hegel.Integers(0, int64(len(statuses)-1)))]
		reason := hegel.Draw(ht, hegel.Text().MaxSize(10))
		message := hegel.Draw(ht, hegel.Text().MaxSize(10))

		wantCondition := cmapi.CertificateRequestCondition{
			Type:               conditionType,
			Status:             status,
			Reason:             reason,
			Message:            message,
			LastTransitionTime: &nowObj,
		}
		for _, cond := range existingConditions {
			if cond.Type == conditionType && cond.Status == status {
				wantCondition.LastTransitionTime = cond.LastTransitionTime
			}
		}

		wantPatch := append([]cmapi.CertificateRequestCondition{}, patchConditions...)
		overwritten := false
		for i, cond := range wantPatch {
			if cond.Type == conditionType {
				wantPatch[i] = wantCondition
				overwritten = true
			}
		}
		if !overwritten {
			wantPatch = append(wantPatch, wantCondition)
		}

		gotPatch := append([]cmapi.CertificateRequestCondition{}, patchConditions...)
		gotCondition, gotTime := SetCertificateRequestStatusCondition(
			clocktesting.NewFakeClock(now),
			existingConditions,
			&gotPatch,
			conditionType,
			status,
			reason,
			message,
		)

		if !reflect.DeepEqual(wantCondition, *gotCondition) {
			ht.Fatalf("returned condition %#v, want %#v", *gotCondition, wantCondition)
		}
		if !gotTime.Equal(&nowObj) {
			ht.Fatalf("returned time %v, want %v", gotTime, nowObj)
		}
		if !reflect.DeepEqual(wantPatch, gotPatch) {
			ht.Fatalf("patch conditions %#v, want %#v", gotPatch, wantPatch)
		}
	}, hegel.WithTestCases(1000))
}
