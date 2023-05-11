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
)

// Update the status with the provided condition details & return
// the added condition.
// NOTE: this code is just a workaround for cmutil only accepting the certificaterequest object
func SetCertificateRequestStatusCondition(
	conditions *[]cmapi.CertificateRequestCondition,
	conditionType cmapi.CertificateRequestConditionType,
	status cmmeta.ConditionStatus,
	reason, message string,
) *cmapi.CertificateRequestCondition {
	cr := cmapi.CertificateRequest{
		Status: cmapi.CertificateRequestStatus{
			Conditions: *conditions,
		},
	}

	cmutil.SetCertificateRequestCondition(&cr, conditionType, status, reason, message)
	condition := cmutil.GetCertificateRequestCondition(&cr, conditionType)

	*conditions = cr.Status.Conditions

	return condition
}
