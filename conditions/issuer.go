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
	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// private struct; only used to implement the GenericIssuer interface
// for use with the cmutil.SetIssuerCondition function
type genericIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Status cmapi.IssuerStatus `json:"status"`
}

func (g *genericIssuer) DeepCopyObject() runtime.Object {
	panic("[HACK]: this function should not get called")
}

func (g *genericIssuer) GetSpec() *cmapi.IssuerSpec {
	panic("[HACK]: this function should not get called")
}

func (g *genericIssuer) GetObjectMeta() *metav1.ObjectMeta {
	return &g.ObjectMeta
}

func (g *genericIssuer) GetStatus() *cmapi.IssuerStatus {
	return &g.Status
}

// Update the status with the provided condition details & return
// the added condition.
// NOTE: this code is just a workaround for cmutil only accepting a GenericIssuer interface
func SetIssuerStatusCondition(
	conditions *[]cmapi.IssuerCondition,
	observedGeneration int64,
	conditionType cmapi.IssuerConditionType,
	status cmmeta.ConditionStatus,
	reason, message string,
) *cmapi.IssuerCondition {
	gi := genericIssuer{
		Status: cmapi.IssuerStatus{
			Conditions: *conditions,
		},
	}

	cmutil.SetIssuerCondition(&gi, observedGeneration, conditionType, status, reason, message)

	*conditions = gi.Status.Conditions

	return GetIssuerStatusCondition(*conditions, conditionType)
}

func GetIssuerStatusCondition(
	conditions []cmapi.IssuerCondition,
	conditionType cmapi.IssuerConditionType,
) *cmapi.IssuerCondition {
	for _, cond := range conditions {
		if cond.Type == conditionType {
			return &cond
		}
	}
	return nil
}
