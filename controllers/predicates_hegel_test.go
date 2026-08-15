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

package controllers_test

import (
	"reflect"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"hegel.dev/go/hegel"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/internal/testapi/api"
)

// drawAnnotations draws nil, an empty map, or a small map with drawn values.
// nil and empty are distinct on purpose: the predicates compare annotations
// with reflect.DeepEqual, for which nil != empty map.
func drawAnnotations(ht *hegel.T) map[string]string {
	switch hegel.Draw(ht, hegel.Integers(0, 3)) {
	case 0:
		return nil
	case 1:
		return map[string]string{}
	default:
		annotations := map[string]string{}
		for _, key := range []string{"annotation-a", "annotation-b"} {
			if hegel.Draw(ht, hegel.Booleans()) {
				annotations[key] = hegel.Draw(ht, hegel.Text().MaxSize(5))
			}
		}
		return annotations
	}
}

func drawLabels(ht *hegel.T) map[string]string {
	labels := map[string]string{}
	if hegel.Draw(ht, hegel.Booleans()) {
		labels["label-a"] = hegel.Draw(ht, hegel.Text().MaxSize(5))
	}
	return labels
}

// maybeMutate returns the original value or a freshly drawn one, so that
// old and new objects agree on each aspect often enough to exercise the
// no-reconcile branch as well as every single-aspect change.
func maybeMutate[V any](ht *hegel.T, original V, draw func(*hegel.T) V) V {
	if hegel.Draw(ht, hegel.Booleans()) {
		return original
	}
	return draw(ht)
}

var conditionStatusPool = []corev1.ConditionStatus{corev1.ConditionTrue, corev1.ConditionFalse, corev1.ConditionUnknown}

func drawConditionStatus(ht *hegel.T) corev1.ConditionStatus {
	return conditionStatusPool[hegel.Draw(ht, hegel.Integers(0, int64(len(conditionStatusPool)-1)))]
}

// drawObject wraps a drawn valid object, replacing it with nil or an object
// of an unexpected type some of the time; the predicates must reconcile
// (return true) whenever either object is not a valid instance of the
// watched type.
func drawObject(ht *hegel.T, valid func(*hegel.T) client.Object) (client.Object, bool) {
	switch hegel.Draw(ht, hegel.Integers(0, 9)) {
	case 0:
		return nil, false
	case 1:
		return &corev1.ConfigMap{}, false
	default:
		return valid(ht), true
	}
}

var certificateRequestConditionTypePool = []cmapi.CertificateRequestConditionType{
	cmapi.CertificateRequestConditionReady,
	cmapi.CertificateRequestConditionApproved,
	cmapi.CertificateRequestConditionDenied,
	"Other",
}

func drawCertificateRequestConditions(ht *hegel.T) []cmapi.CertificateRequestCondition {
	conditions := []cmapi.CertificateRequestCondition{}
	for _, conditionType := range certificateRequestConditionTypePool {
		if !hegel.Draw(ht, hegel.Booleans()) {
			continue
		}
		conditions = append(conditions, cmapi.CertificateRequestCondition{
			Type:   conditionType,
			Status: cmmeta.ConditionStatus(drawConditionStatus(ht)),
			Reason: hegel.Draw(ht, hegel.Text().MaxSize(5)),
		})
	}
	return conditions
}

// TestCertificateRequestPredicateProperty: CertificateRequestPredicate must
// reconcile iff either object is missing or of the wrong type, the condition
// count changed, a non-Ready condition disappeared or changed status, or the
// annotations changed — and must NOT reconcile on label changes, reason-only
// changes, or Ready condition changes. Replaces the eight-example
// TestCertificateRequestPredicate table.
//
// Note the pinned rule diverges from the predicate's doc comment: because
// conditions of type Ready are skipped, an update replacing a Ready
// condition with a different type (leaving the count unchanged) does not
// trigger, although a condition was added and another removed.
func TestCertificateRequestPredicateProperty(t *testing.T) {
	predicate := controllers.CertificateRequestPredicate{}

	hegel.Test(t, func(ht *hegel.T) {
		var oldCR, newCR *cmapi.CertificateRequest
		objectOld, oldValid := drawObject(ht, func(ht *hegel.T) client.Object {
			oldCR = &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "cr1",
					Annotations: drawAnnotations(ht),
					Labels:      drawLabels(ht),
				},
				Status: cmapi.CertificateRequestStatus{Conditions: drawCertificateRequestConditions(ht)},
			}
			return oldCR
		})
		objectNew, newValid := drawObject(ht, func(ht *hegel.T) client.Object {
			annotations := drawAnnotations(ht)
			conditions := drawCertificateRequestConditions(ht)
			if oldCR != nil {
				annotations = maybeMutate(ht, oldCR.Annotations, drawAnnotations)
				conditions = maybeMutate(ht, oldCR.Status.Conditions, drawCertificateRequestConditions)
			}
			newCR = &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "cr1",
					Annotations: annotations,
					Labels:      drawLabels(ht),
				},
				Status: cmapi.CertificateRequestStatus{Conditions: conditions},
			}
			return newCR
		})

		want := true
		if oldValid && newValid {
			want = wantCertificateRequestReconcile(oldCR, newCR)
		}

		got := predicate.Update(event.UpdateEvent{ObjectOld: objectOld, ObjectNew: objectNew})
		if got != want {
			ht.Fatalf("Update(old=%#v, new=%#v) = %v, want %v", objectOld, objectNew, got, want)
		}
	}, hegel.WithTestCases(1000))
}

func wantCertificateRequestReconcile(oldCR, newCR *cmapi.CertificateRequest) bool {
	if len(oldCR.Status.Conditions) != len(newCR.Status.Conditions) {
		return true
	}
	newStatusByType := map[cmapi.CertificateRequestConditionType]cmmeta.ConditionStatus{}
	for _, cond := range newCR.Status.Conditions {
		if _, ok := newStatusByType[cond.Type]; !ok {
			newStatusByType[cond.Type] = cond.Status
		}
	}
	for _, cond := range oldCR.Status.Conditions {
		if cond.Type == cmapi.CertificateRequestConditionReady {
			continue
		}
		newStatus, ok := newStatusByType[cond.Type]
		if !ok || newStatus != cond.Status {
			return true
		}
	}
	return !reflect.DeepEqual(newCR.Annotations, oldCR.Annotations)
}

var certificateSigningRequestConditionTypePool = []certificatesv1.RequestConditionType{
	certificatesv1.CertificateApproved,
	certificatesv1.CertificateDenied,
	certificatesv1.CertificateFailed,
	"Other",
}

func drawCertificateSigningRequestConditions(ht *hegel.T) []certificatesv1.CertificateSigningRequestCondition {
	conditions := []certificatesv1.CertificateSigningRequestCondition{}
	for _, conditionType := range certificateSigningRequestConditionTypePool {
		if !hegel.Draw(ht, hegel.Booleans()) {
			continue
		}
		conditions = append(conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:   conditionType,
			Status: drawConditionStatus(ht),
			Reason: hegel.Draw(ht, hegel.Text().MaxSize(5)),
		})
	}
	return conditions
}

// TestCertificateSigningRequestPredicateProperty: same rule as the
// CertificateRequest predicate but without the Ready exemption — any
// condition disappearing or changing status triggers, as do annotation
// changes; label and reason-only changes do not. Replaces the nine-example
// TestCertificateSigningRequestPredicate table.
func TestCertificateSigningRequestPredicateProperty(t *testing.T) {
	predicate := controllers.CertificateSigningRequestPredicate{}

	hegel.Test(t, func(ht *hegel.T) {
		var oldCSR, newCSR *certificatesv1.CertificateSigningRequest
		objectOld, oldValid := drawObject(ht, func(ht *hegel.T) client.Object {
			oldCSR = &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "csr1",
					Annotations: drawAnnotations(ht),
					Labels:      drawLabels(ht),
				},
				Status: certificatesv1.CertificateSigningRequestStatus{Conditions: drawCertificateSigningRequestConditions(ht)},
			}
			return oldCSR
		})
		objectNew, newValid := drawObject(ht, func(ht *hegel.T) client.Object {
			annotations := drawAnnotations(ht)
			conditions := drawCertificateSigningRequestConditions(ht)
			if oldCSR != nil {
				annotations = maybeMutate(ht, oldCSR.Annotations, drawAnnotations)
				conditions = maybeMutate(ht, oldCSR.Status.Conditions, drawCertificateSigningRequestConditions)
			}
			newCSR = &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "csr1",
					Annotations: annotations,
					Labels:      drawLabels(ht),
				},
				Status: certificatesv1.CertificateSigningRequestStatus{Conditions: conditions},
			}
			return newCSR
		})

		want := true
		if oldValid && newValid {
			want = wantCertificateSigningRequestReconcile(oldCSR, newCSR)
		}

		got := predicate.Update(event.UpdateEvent{ObjectOld: objectOld, ObjectNew: objectNew})
		if got != want {
			ht.Fatalf("Update(old=%#v, new=%#v) = %v, want %v", objectOld, objectNew, got, want)
		}
	}, hegel.WithTestCases(1000))
}

func wantCertificateSigningRequestReconcile(oldCSR, newCSR *certificatesv1.CertificateSigningRequest) bool {
	if len(oldCSR.Status.Conditions) != len(newCSR.Status.Conditions) {
		return true
	}
	newStatusByType := map[certificatesv1.RequestConditionType]corev1.ConditionStatus{}
	for _, cond := range newCSR.Status.Conditions {
		if _, ok := newStatusByType[cond.Type]; !ok {
			newStatusByType[cond.Type] = cond.Status
		}
	}
	for _, cond := range oldCSR.Status.Conditions {
		newStatus, ok := newStatusByType[cond.Type]
		if !ok || newStatus != cond.Status {
			return true
		}
	}
	return !reflect.DeepEqual(newCSR.Annotations, oldCSR.Annotations)
}

var issuerConditionTypePool = []string{v1alpha1.IssuerConditionTypeReady, "Other", "Random"}

func drawIssuerConditions(ht *hegel.T) []metav1.Condition {
	conditions := []metav1.Condition{}
	for _, conditionType := range issuerConditionTypePool {
		if !hegel.Draw(ht, hegel.Booleans()) {
			continue
		}
		conditions = append(conditions, metav1.Condition{
			Type:               conditionType,
			Status:             metav1.ConditionStatus(drawConditionStatus(ht)),
			Reason:             hegel.Draw(ht, hegel.Text().MaxSize(5)),
			ObservedGeneration: int64(hegel.Draw(ht, hegel.Integers(0, 3))),
		})
	}
	return conditions
}

func drawIssuer(ht *hegel.T) *api.TestIssuer {
	return &api.TestIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "issuer-1",
			Generation:  int64(hegel.Draw(ht, hegel.Integers(0, 3))),
			Annotations: drawAnnotations(ht),
		},
		Status: v1alpha1.IssuerStatus{Conditions: drawIssuerConditions(ht)},
	}
}

func mutateIssuer(ht *hegel.T, oldIssuer *api.TestIssuer) *api.TestIssuer {
	return &api.TestIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "issuer-1",
			Generation:  maybeMutate(ht, oldIssuer.Generation, func(ht *hegel.T) int64 { return int64(hegel.Draw(ht, hegel.Integers(0, 3))) }),
			Annotations: maybeMutate(ht, oldIssuer.Annotations, drawAnnotations),
		},
		Status: v1alpha1.IssuerStatus{Conditions: maybeMutate(ht, oldIssuer.Status.Conditions, drawIssuerConditions)},
	}
}

func firstReadyCondition(conditions []metav1.Condition) *metav1.Condition {
	for _, cond := range conditions {
		if cond.Type == v1alpha1.IssuerConditionTypeReady {
			return &cond
		}
	}
	return nil
}

// TestLinkedIssuerPredicateProperty: LinkedIssuerPredicate (Issuer events
// that wake the CertificateRequest reconciler) must reconcile iff either
// object is missing or of the wrong type, the Ready condition appeared or
// disappeared, or its Status or ObservedGeneration changed. Changes to any
// other condition, to reason/message, to annotations or to the generation
// must not trigger. Replaces the seven-example TestLinkedIssuerPredicate
// table.
func TestLinkedIssuerPredicateProperty(t *testing.T) {
	predicate := controllers.LinkedIssuerPredicate{}

	hegel.Test(t, func(ht *hegel.T) {
		var oldIssuer, newIssuer *api.TestIssuer
		objectOld, oldValid := drawObject(ht, func(ht *hegel.T) client.Object {
			oldIssuer = drawIssuer(ht)
			return oldIssuer
		})
		objectNew, newValid := drawObject(ht, func(ht *hegel.T) client.Object {
			if oldIssuer != nil {
				newIssuer = mutateIssuer(ht, oldIssuer)
			} else {
				newIssuer = drawIssuer(ht)
			}
			return newIssuer
		})

		want := true
		if oldValid && newValid {
			readyOld := firstReadyCondition(oldIssuer.Status.Conditions)
			readyNew := firstReadyCondition(newIssuer.Status.Conditions)
			switch {
			case readyOld == nil && readyNew == nil:
				want = false
			case readyOld == nil || readyNew == nil:
				want = true
			default:
				want = readyNew.Status != readyOld.Status || readyNew.ObservedGeneration != readyOld.ObservedGeneration
			}
		}

		got := predicate.Update(event.UpdateEvent{ObjectOld: objectOld, ObjectNew: objectNew})
		if got != want {
			ht.Fatalf("Update(old=%#v, new=%#v) = %v, want %v", objectOld, objectNew, got, want)
		}
	}, hegel.WithTestCases(1000))
}

// TestIssuerPredicateProperty: IssuerPredicate (Issuer events that wake the
// Issuer reconciler) must reconcile iff either object is missing or of the
// wrong type, the generation changed, the Ready condition appeared or
// disappeared, or the annotations changed. Ready status changes alone must
// not trigger — those are the reconciler's own status updates. Replaces the
// six-example TestIssuerPredicate table.
func TestIssuerPredicateProperty(t *testing.T) {
	predicate := controllers.IssuerPredicate{}

	hegel.Test(t, func(ht *hegel.T) {
		var oldIssuer, newIssuer *api.TestIssuer
		objectOld, oldValid := drawObject(ht, func(ht *hegel.T) client.Object {
			oldIssuer = drawIssuer(ht)
			return oldIssuer
		})
		objectNew, newValid := drawObject(ht, func(ht *hegel.T) client.Object {
			if oldIssuer != nil {
				newIssuer = mutateIssuer(ht, oldIssuer)
			} else {
				newIssuer = drawIssuer(ht)
			}
			return newIssuer
		})

		want := true
		if oldValid && newValid && oldIssuer.Generation == newIssuer.Generation {
			readyOld := firstReadyCondition(oldIssuer.Status.Conditions)
			readyNew := firstReadyCondition(newIssuer.Status.Conditions)
			if (readyOld == nil) == (readyNew == nil) {
				want = !reflect.DeepEqual(newIssuer.Annotations, oldIssuer.Annotations)
			}
		}
		got := predicate.Update(event.UpdateEvent{ObjectOld: objectOld, ObjectNew: objectNew})
		if got != want {
			ht.Fatalf("Update(old=%#v, new=%#v) = %v, want %v", objectOld, objectNew, got, want)
		}
	}, hegel.WithTestCases(1000))
}
