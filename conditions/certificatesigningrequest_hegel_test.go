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

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"

	"hegel.dev/go/hegel"
)

func drawCertificateSigningRequestConditionSet(ht *hegel.T, statuses []corev1.ConditionStatus) []certificatesv1.CertificateSigningRequestCondition {
	conditions := []certificatesv1.CertificateSigningRequestCondition{}
	for _, conditionType := range conditionTypePool {
		if !hegel.Draw(ht, hegel.Booleans()) {
			continue
		}
		conditions = append(conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:               certificatesv1.RequestConditionType(conditionType),
			Status:             statuses[hegel.Draw(ht, hegel.Integers(0, int64(len(statuses)-1)))],
			Reason:             hegel.Draw(ht, hegel.Text().MaxSize(10)),
			Message:            hegel.Draw(ht, hegel.Text().MaxSize(10)),
			LastUpdateTime:     metav1.NewTime(drawTime(ht)),
			LastTransitionTime: metav1.NewTime(drawTime(ht)),
		})
	}
	return conditions
}

// TestSetCertificateSigningRequestStatusConditionProperty: the same
// set-or-overwrite rule as SetIssuerStatusCondition, for CSR conditions,
// with one addition: LastUpdateTime is always the clock's now, while
// LastTransitionTime is preserved from the existing condition of the same
// type iff its status already matched. Replaces the four-example
// TestSetCertificateSigningRequestStatusCondition table.
func TestSetCertificateSigningRequestStatusConditionProperty(t *testing.T) {
	statuses := []corev1.ConditionStatus{corev1.ConditionTrue, corev1.ConditionFalse, corev1.ConditionUnknown}

	hegel.Test(t, func(ht *hegel.T) {
		now := drawTime(ht)
		nowObj := metav1.NewTime(now)

		existingConditions := drawCertificateSigningRequestConditionSet(ht, statuses)
		patchConditions := drawCertificateSigningRequestConditionSet(ht, statuses)

		conditionType := certificatesv1.RequestConditionType(conditionTypePool[hegel.Draw(ht, hegel.Integers(0, int64(len(conditionTypePool)-1)))])
		status := statuses[hegel.Draw(ht, hegel.Integers(0, int64(len(statuses)-1)))]
		reason := hegel.Draw(ht, hegel.Text().MaxSize(10))
		message := hegel.Draw(ht, hegel.Text().MaxSize(10))

		wantCondition := certificatesv1.CertificateSigningRequestCondition{
			Type:               conditionType,
			Status:             status,
			Reason:             reason,
			Message:            message,
			LastUpdateTime:     nowObj,
			LastTransitionTime: nowObj,
		}
		for _, cond := range existingConditions {
			if cond.Type == conditionType && cond.Status == status {
				wantCondition.LastTransitionTime = cond.LastTransitionTime
			}
		}

		wantPatch := append([]certificatesv1.CertificateSigningRequestCondition{}, patchConditions...)
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

		gotPatch := append([]certificatesv1.CertificateSigningRequestCondition{}, patchConditions...)
		gotCondition, gotTime := SetCertificateSigningRequestStatusCondition(
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
