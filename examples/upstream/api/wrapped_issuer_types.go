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

package api

import (
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
)

type GenericWrappedIssuer interface {
	v1alpha1.WrappedIssuer
	IssuerSpec() *cmapi.IssuerSpec
}

// +kubebuilder:object:root=true
// +kubebuilder:skip

type WrappedIssuer struct {
	cmapi.Issuer
}

func (i *WrappedIssuer) GetConditions() (conditions []metav1.Condition) {
	for _, condition := range i.Issuer.Status.Conditions {
		conditions = append(conditions, metav1.Condition{
			Type:               string(condition.Type),
			Status:             metav1.ConditionStatus(condition.Status),
			ObservedGeneration: condition.ObservedGeneration,
			LastTransitionTime: ptr.Deref(condition.LastTransitionTime, metav1.Time{}),
			Reason:             condition.Reason,
			Message:            condition.Message,
		})
	}
	return conditions
}

func (i *WrappedIssuer) GetIssuerTypeIdentifier() string {
	return "issuers.cert-manager.io"
}

func (i *WrappedIssuer) Unwrap() client.Object {
	return &i.Issuer
}

func (i *WrappedIssuer) IssuerSpec() *cmapi.IssuerSpec {
	return &i.Issuer.Spec
}

var _ GenericWrappedIssuer = &WrappedIssuer{}
