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

package controllers

import (
	"reflect"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
)

// This predicate is used to indicate when a CertificateRequest event should
// trigger a reconciliation of itself.
//
// In these cases we want to trigger:
// - an annotation changed/ was added or removed
// - a status condition was added or removed
// - a status condition that does not have type == Ready was changed (aka. other Status value)
type CertificateRequestPredicate struct {
	predicate.Funcs
}

func (CertificateRequestPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		// a reference object is missing, just reconcile to be safe
		return true
	}

	oldCr, oldOk := e.ObjectOld.(*cmapi.CertificateRequest)
	newCr, newOk := e.ObjectNew.(*cmapi.CertificateRequest)
	if !oldOk || !newOk {
		// a reference object is invalid, just reconcile to be safe
		return true
	}

	if len(oldCr.Status.Conditions) != len(newCr.Status.Conditions) {
		// Fail fast in case we are certain a non-ready condition was added or removed.
		return true
	}

	for _, oldCond := range oldCr.Status.Conditions {
		if oldCond.Type == cmapi.CertificateRequestConditionReady {
			// we can skip the Ready conditions
			continue
		}

		newCond := cmutil.GetCertificateRequestCondition(newCr, oldCond.Type)
		if (newCond == nil) || (oldCond.Status != newCond.Status) {
			// we found a missing or changed condition
			return true
		}
	}

	// check if any of the annotations changed
	return !reflect.DeepEqual(e.ObjectNew.GetAnnotations(), e.ObjectOld.GetAnnotations())
}

// This predicate is used to indicate when a CertificateSigningRequest event should
// trigger a reconciliation of itself.
//
// In these cases we want to trigger:
// - an annotation changed/ was added or removed
// - a status condition was added or removed
// - a status condition was changed
type CertificateSigningRequestPredicate struct {
	predicate.Funcs
}

func (CertificateSigningRequestPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		// a reference object is missing, just reconcile to be safe
		return true
	}

	oldCr, oldOk := e.ObjectOld.(*certificatesv1.CertificateSigningRequest)
	newCr, newOk := e.ObjectNew.(*certificatesv1.CertificateSigningRequest)
	if !oldOk || !newOk {
		// a reference object is invalid, just reconcile to be safe
		return true
	}

	if len(oldCr.Status.Conditions) != len(newCr.Status.Conditions) {
		// Fail fast in case we are certain a non-ready condition was added or removed.
		return true
	}

	for _, oldCond := range oldCr.Status.Conditions {
		newCond := conditions.GetCertificateSigningRequestStatusCondition(newCr.Status.Conditions, oldCond.Type)
		if (newCond == nil) || (oldCond.Status != newCond.Status) {
			// we found a missing or changed condition
			return true
		}
	}

	// check if any of the annotations changed
	return !reflect.DeepEqual(e.ObjectNew.GetAnnotations(), e.ObjectOld.GetAnnotations())
}

// Predicate for Issuer events that should trigger the CertificateRequest reconciler
//
// In these cases we want to trigger:
// - the Ready condition was added/ removed
// - the Ready condition's Status property changed
// - the Ready condition's observed generation changed
type LinkedIssuerPredicate struct {
	predicate.Funcs
}

// Update implements default UpdateEvent filter for validating resource version change.
func (LinkedIssuerPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		// a reference object is missing, just reconcile to be safe
		return true
	}

	issuerOld, okOld := e.ObjectOld.(v1alpha1.Issuer)
	issuerNew, okNew := e.ObjectNew.(v1alpha1.Issuer)
	if !okOld || !okNew {
		// a reference object is invalid, just reconcile to be safe
		return true
	}

	readyOld := conditions.GetIssuerStatusCondition(
		issuerOld.GetConditions(),
		v1alpha1.IssuerConditionTypeReady,
	)

	readyNew := conditions.GetIssuerStatusCondition(
		issuerNew.GetConditions(),
		v1alpha1.IssuerConditionTypeReady,
	)

	if readyOld == nil || readyNew == nil {
		// the ready condition is not present in the old and/or new version
		// we only want to reconcile if one of the two conditions is not nil
		return readyOld != nil || readyNew != nil
	}

	return readyNew.Status != readyOld.Status || readyNew.ObservedGeneration != readyOld.ObservedGeneration
}

// Predicate for Issuer events that should trigger the Issuer reconciler
//
// In these cases we want to trigger:
// - an annotation changed/ was added or removed
// - the generation changed
// - the Ready condition was added/ removed
type IssuerPredicate struct {
	predicate.Funcs
}

// Update implements default UpdateEvent filter for validating generation change.
func (IssuerPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		// a reference object is missing, just reconcile to be safe
		return true
	}

	if e.ObjectNew.GetGeneration() != e.ObjectOld.GetGeneration() {
		// we noticed a generation change
		return true
	}

	issuerOld, okOld := e.ObjectOld.(v1alpha1.Issuer)
	issuerNew, okNew := e.ObjectNew.(v1alpha1.Issuer)
	if !okOld || !okNew {
		// a reference object is invalid, just reconcile to be safe
		return true
	}

	readyOld := conditions.GetIssuerStatusCondition(
		issuerOld.GetConditions(),
		v1alpha1.IssuerConditionTypeReady,
	)

	readyNew := conditions.GetIssuerStatusCondition(
		issuerNew.GetConditions(),
		v1alpha1.IssuerConditionTypeReady,
	)

	if (readyOld == nil && readyNew != nil) ||
		(readyOld != nil && readyNew == nil) {
		// the ready condition is not present in the old or new version but
		// is present in the new or old version
		return true
	}

	// check if any of the annotations changed
	return !reflect.DeepEqual(e.ObjectNew.GetAnnotations(), e.ObjectOld.GetAnnotations())
}
