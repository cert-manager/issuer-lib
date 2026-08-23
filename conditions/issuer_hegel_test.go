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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"

	"hegel.dev/go/hegel"
)

// drawTime draws an arbitrary whole-second UTC time between 1970 and 2100.
// The clock time is drawn (rather than time.Now()) so that any incorrect use
// of time.Now() in the code under test is detected deterministically, which
// is what the old tests' rand-based randomTime helper approximated.
func drawTime(ht *hegel.T) time.Time {
	return time.Unix(int64(hegel.Draw(ht, hegel.Integers(0, 4102444800))), 0).UTC()
}

// drawConditionSet draws a set of conditions with unique types (duplicate
// types in a condition list are invalid per the Kubernetes API conventions,
// and the setter's overwrite semantics are only well defined without them).
func drawConditionSet(ht *hegel.T, statuses []metav1.ConditionStatus) []metav1.Condition {
	conditions := []metav1.Condition{}
	for _, conditionType := range conditionTypePool {
		if !hegel.Draw(ht, hegel.Booleans()) {
			continue
		}
		conditions = append(conditions, metav1.Condition{
			Type:               conditionType,
			Status:             statuses[hegel.Draw(ht, hegel.Integers(0, int64(len(statuses)-1)))],
			Reason:             hegel.Draw(ht, hegel.Text().MaxSize(10)),
			Message:            hegel.Draw(ht, hegel.Text().MaxSize(10)),
			ObservedGeneration: int64(hegel.Draw(ht, hegel.Integers(0, 1000))),
			LastTransitionTime: metav1.NewTime(drawTime(ht)),
		})
	}
	return conditions
}

var conditionTypePool = []string{"Ready", "Approved", "Denied", "Other"}

// TestSetIssuerStatusConditionProperty: for any existing and patch condition
// sets, SetIssuerStatusCondition returns a condition carrying exactly the
// requested type, status, reason, message and observed generation; its
// LastTransitionTime is preserved from the existing condition of the same
// type iff that condition already had the requested status, and is the
// clock's now otherwise. The patch slice gets the condition overwritten in
// place if the type is already present, appended otherwise, with every other
// entry untouched. Replaces the four-example TestSetIssuerStatusCondition
// table, whose rows were instances of this rule.
func TestSetIssuerStatusConditionProperty(t *testing.T) {
	statuses := []metav1.ConditionStatus{metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionUnknown}

	hegel.Test(t, func(ht *hegel.T) {
		now := drawTime(ht)
		nowObj := metav1.NewTime(now)

		existingConditions := drawConditionSet(ht, statuses)
		patchConditions := drawConditionSet(ht, statuses)

		conditionType := conditionTypePool[hegel.Draw(ht, hegel.Integers(0, int64(len(conditionTypePool)-1)))]
		status := statuses[hegel.Draw(ht, hegel.Integers(0, int64(len(statuses)-1)))]
		reason := hegel.Draw(ht, hegel.Text().MaxSize(10))
		message := hegel.Draw(ht, hegel.Text().MaxSize(10))
		observedGeneration := int64(hegel.Draw(ht, hegel.Integers(0, 1000)))

		wantCondition := metav1.Condition{
			Type:               conditionType,
			Status:             status,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: observedGeneration,
			LastTransitionTime: nowObj,
		}
		for _, cond := range existingConditions {
			if cond.Type == conditionType && cond.Status == status {
				wantCondition.LastTransitionTime = cond.LastTransitionTime
			}
		}

		wantPatch := append([]metav1.Condition{}, patchConditions...)
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

		gotPatch := append([]metav1.Condition{}, patchConditions...)
		gotCondition, gotTime := SetIssuerStatusCondition(
			clocktesting.NewFakeClock(now),
			existingConditions,
			&gotPatch,
			observedGeneration,
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
