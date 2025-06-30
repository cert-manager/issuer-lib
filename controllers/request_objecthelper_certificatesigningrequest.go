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
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/ssaclient"
)

type certificatesigningRequestObjectHelper struct {
	readOnlyObj *certificatesv1.CertificateSigningRequest
}

var _ RequestObjectHelper = &certificatesigningRequestObjectHelper{}

func (c *certificatesigningRequestObjectHelper) IsApproved() bool {
	return util.CertificateSigningRequestIsApproved(c.readOnlyObj)
}

func (c *certificatesigningRequestObjectHelper) IsDenied() bool {
	return util.CertificateSigningRequestIsDenied(c.readOnlyObj)
}

func (c *certificatesigningRequestObjectHelper) IsReady() bool {
	return len(c.readOnlyObj.Status.Certificate) > 0
}

func (c *certificatesigningRequestObjectHelper) IsFailed() bool {
	return util.CertificateSigningRequestIsFailed(c.readOnlyObj)
}

func (c *certificatesigningRequestObjectHelper) RequestObject() signer.CertificateRequestObject {
	return signer.CertificateRequestObjectFromCertificateSigningRequest(c.readOnlyObj)
}

func (c *certificatesigningRequestObjectHelper) NewPatch(
	clock clock.PassiveClock,
	fieldOwner string,
	eventRecorder record.EventRecorder,
) RequestPatchHelper {
	return &certificatesigningRequestPatchHelper{
		clock:         clock,
		readOnlyObj:   c.readOnlyObj,
		fieldOwner:    fieldOwner,
		patch:         &certificatesv1.CertificateSigningRequestStatus{},
		eventRecorder: eventRecorder,
	}
}

type certificatesigningRequestPatchHelper struct {
	clock       clock.PassiveClock
	readOnlyObj *certificatesv1.CertificateSigningRequest
	fieldOwner  string

	patch         *certificatesv1.CertificateSigningRequestStatus
	eventRecorder record.EventRecorder
}

var _ RequestPatchHelper = &certificatesigningRequestPatchHelper{}
var _ RequestPatch = &certificatesigningRequestPatchHelper{}
var _ CertificateSigningRequestPatch = &certificatesigningRequestPatchHelper{}

func (c *certificatesigningRequestPatchHelper) setCondition(
	conditionType certificatesv1.RequestConditionType,
	status corev1.ConditionStatus,
	reason, message string,
) string {
	condition, _ := conditions.SetCertificateSigningRequestStatusCondition(
		c.clock,
		c.readOnlyObj.Status.Conditions,
		&c.patch.Conditions,
		conditionType, status,
		reason, message,
	)
	return condition.Message
}

func (c *certificatesigningRequestPatchHelper) SetInitializing() bool {
	return false
}

func (c *certificatesigningRequestPatchHelper) SetWaitingForIssuerExist(err error) {
	message := fmt.Sprintf("%s. Waiting for it to be created.", err)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestWaitingForIssuerExist, message)
}

func (c *certificatesigningRequestPatchHelper) SetWaitingForIssuerReadyNoCondition() {
	message := "Waiting for issuer to become ready. Current issuer ready condition: <none>."
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestWaitingForIssuerReady, message)
}

func (c *certificatesigningRequestPatchHelper) SetWaitingForIssuerReadyOutdated() {
	message := "Waiting for issuer to become ready. Current issuer ready condition is outdated."
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestWaitingForIssuerReady, message)
}

func (c *certificatesigningRequestPatchHelper) SetWaitingForIssuerReadyNotReady(cond *metav1.Condition) {
	message := fmt.Sprintf("Waiting for issuer to become ready. Current issuer ready condition is \"%s\": %s.", cond.Reason, cond.Message)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestWaitingForIssuerReady, message)
}

func (c *certificatesigningRequestPatchHelper) SetCustomCondition(
	conditionType string,
	conditionStatus metav1.ConditionStatus,
	conditionReason string, conditionMessage string,
) bool {
	c.setCondition(
		certificatesv1.RequestConditionType(conditionType),
		corev1.ConditionStatus(conditionStatus),
		conditionReason,
		conditionMessage,
	)

	// check if the custom condition transitioned
	currentCustom := conditions.GetCertificateSigningRequestStatusCondition(c.readOnlyObj.Status.Conditions, certificatesv1.RequestConditionType(conditionType))
	didCustomConditionTransition := currentCustom == nil || currentCustom.Status != corev1.ConditionStatus(conditionStatus)
	return didCustomConditionTransition
}

func (c *certificatesigningRequestPatchHelper) SetPending(reason string) {
	message := fmt.Sprintf("Signing still in progress. Reason: %s", reason)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeWarning, eventRequestRetryable, message)
}

func (c *certificatesigningRequestPatchHelper) SetUnexpectedError(err error) {
	message := "Got an unexpected error while processing the CertificateSigningRequest"
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeWarning, eventRequestUnexpectedError, message)
}

func (c *certificatesigningRequestPatchHelper) SetRetryableError(err error) {
	message := fmt.Sprintf("Failed to sign CertificateSigningRequest, will retry: %s", err)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeWarning, eventRequestRetryableError, message)
}

func (c *certificatesigningRequestPatchHelper) SetPermanentError(err error) {
	message := c.setCondition(
		certificatesv1.CertificateFailed,
		corev1.ConditionTrue,
		cmapi.CertificateRequestReasonFailed,
		fmt.Sprintf("CertificateSigningRequest has failed permanently: %s", err),
	)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeWarning, eventRequestPermanentError, message)
}

func (c *certificatesigningRequestPatchHelper) SetIssued(bundle signer.PEMBundle) {
	c.patch.Certificate = bundle.ChainPEM
	message := "Succeeded signing the CertificateSigningRequest"
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestIssued, message)
}

func (c *certificatesigningRequestPatchHelper) Patch() (client.Object, client.Patch, error) {
	csr, patch, err := ssaclient.GenerateCertificateSigningRequestStatusPatch(
		c.readOnlyObj.Name,
		c.readOnlyObj.Namespace,
		c.patch,
	)
	return &csr, patch, err
}

func (c *certificatesigningRequestPatchHelper) CertificateSigningRequestPatch() *certificatesv1.CertificateSigningRequestStatus {
	return c.patch
}
