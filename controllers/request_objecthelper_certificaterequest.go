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

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/ssaclient"
)

type certificateRequestObjectHelper struct {
	readOnlyObj               *cmapi.CertificateRequest
	setCAOnCertificateRequest bool
}

var _ RequestObjectHelper = &certificateRequestObjectHelper{}

func (c *certificateRequestObjectHelper) IsApproved() bool {
	return cmutil.CertificateRequestIsApproved(c.readOnlyObj)
}

func (c *certificateRequestObjectHelper) IsDenied() bool {
	return cmutil.CertificateRequestHasCondition(c.readOnlyObj, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	})
}

func (c *certificateRequestObjectHelper) IsReady() bool {
	return cmutil.CertificateRequestHasCondition(c.readOnlyObj, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	})
}

func (c *certificateRequestObjectHelper) IsFailed() bool {
	return cmutil.CertificateRequestHasCondition(c.readOnlyObj, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	})
}

func (c *certificateRequestObjectHelper) RequestObject() signer.CertificateRequestObject {
	return signer.CertificateRequestObjectFromCertificateRequest(c.readOnlyObj)
}

func (c *certificateRequestObjectHelper) NewPatch(
	clock clock.PassiveClock,
	fieldOwner string,
	eventRecorder record.EventRecorder,
) RequestPatchHelper {
	return &certificateRequestPatchHelper{
		clock:                     clock,
		readOnlyObj:               c.readOnlyObj,
		fieldOwner:                fieldOwner,
		setCAOnCertificateRequest: c.setCAOnCertificateRequest,
		patch:                     &cmapi.CertificateRequestStatus{},
		eventRecorder:             eventRecorder,
	}
}

type certificateRequestPatchHelper struct {
	clock                     clock.PassiveClock
	readOnlyObj               *cmapi.CertificateRequest
	fieldOwner                string
	setCAOnCertificateRequest bool

	patch         *cmapi.CertificateRequestStatus
	eventRecorder record.EventRecorder
}

var _ RequestPatchHelper = &certificateRequestPatchHelper{}
var _ RequestPatch = &certificateRequestPatchHelper{}
var _ CertificateRequestPatch = &certificateRequestPatchHelper{}

func (c *certificateRequestPatchHelper) setCondition(
	conditionType cmapi.CertificateRequestConditionType,
	status cmmeta.ConditionStatus,
	reason, message string,
) (string, *metav1.Time) {
	condition, updatedAt := conditions.SetCertificateRequestStatusCondition(
		c.clock,
		c.readOnlyObj.Status.Conditions,
		&c.patch.Conditions,
		conditionType, status,
		reason, message,
	)
	return condition.Message, updatedAt
}

func (c *certificateRequestPatchHelper) SetInitializing() bool {
	// If the CertificateRequest is already denied, we initialize/ overwrite to a failed Reason=Denied
	// condition.
	if cmutil.CertificateRequestIsDenied(c.readOnlyObj) {
		message, failedAt := c.setCondition(
			cmapi.CertificateRequestConditionReady,
			cmmeta.ConditionFalse,
			cmapi.CertificateRequestReasonDenied,
			"Detected that the CertificateRequest is denied, so it will never be Ready.",
		)
		c.patch.FailureTime = failedAt.DeepCopy()
		c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeWarning, eventRequestPermanentError, message)
		return true
	}

	if ready := cmutil.GetCertificateRequestCondition(
		c.readOnlyObj,
		cmapi.CertificateRequestConditionReady,
	); ready != nil {
		return false
	}

	c.setCondition(
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionUnknown,
		v1alpha1.CertificateRequestConditionReasonInitializing,
		fmt.Sprintf("%s has started reconciling this CertificateRequest", c.fieldOwner),
	)
	return true
}

func (c *certificateRequestPatchHelper) SetWaitingForIssuerExist(err error) {
	message, _ := c.setCondition(
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonPending,
		fmt.Sprintf("%s. Waiting for it to be created.", err),
	)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestWaitingForIssuerExist, message)
}

func (c *certificateRequestPatchHelper) SetWaitingForIssuerReadyNoCondition() {
	message, _ := c.setCondition(
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonPending,
		"Waiting for issuer to become ready. Current issuer ready condition: <none>.",
	)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestWaitingForIssuerReady, message)
}

func (c *certificateRequestPatchHelper) SetWaitingForIssuerReadyOutdated() {
	message, _ := c.setCondition(
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonPending,
		"Waiting for issuer to become ready. Current issuer ready condition is outdated.",
	)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestWaitingForIssuerReady, message)
}

func (c *certificateRequestPatchHelper) SetWaitingForIssuerReadyNotReady(cond *metav1.Condition) {
	message, _ := c.setCondition(
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonPending,
		fmt.Sprintf("Waiting for issuer to become ready. Current issuer ready condition is \"%s\": %s.", cond.Reason, cond.Message),
	)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestWaitingForIssuerReady, message)
}

func (c *certificateRequestPatchHelper) SetCustomCondition(
	conditionType string,
	conditionStatus metav1.ConditionStatus,
	conditionReason string, conditionMessage string,
) bool {
	c.setCondition(
		cmapi.CertificateRequestConditionType(conditionType),
		cmmeta.ConditionStatus(conditionStatus),
		conditionReason,
		conditionMessage,
	)

	// check if the custom condition transitioned
	currentCustom := cmutil.GetCertificateRequestCondition(c.readOnlyObj, cmapi.CertificateRequestConditionType(conditionType))
	didCustomConditionTransition := currentCustom == nil || currentCustom.Status != cmmeta.ConditionStatus(conditionStatus)
	return didCustomConditionTransition
}

func (c *certificateRequestPatchHelper) SetUnexpectedError(err error) {
	message := "Got an unexpected error while processing the CertificateRequest"
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeWarning, eventRequestUnexpectedError, message)
}

func (c *certificateRequestPatchHelper) SetPending(reason string) {
	message, _ := c.setCondition(
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonPending,
		fmt.Sprintf("Signing still in progress. Reason: %s", reason),
	)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeWarning, eventRequestRetryableError, message)
}

func (c *certificateRequestPatchHelper) SetRetryableError(err error) {
	message, _ := c.setCondition(
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonPending,
		fmt.Sprintf("Failed to sign CertificateRequest, will retry: %s", err),
	)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeWarning, eventRequestRetryableError, message)
}

func (c *certificateRequestPatchHelper) SetPermanentError(err error) {
	message, failedAt := c.setCondition(
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonFailed,
		fmt.Sprintf("Failed permanently to sign CertificateRequest: %s", err),
	)
	c.patch.FailureTime = failedAt.DeepCopy()
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeWarning, eventRequestPermanentError, message)
}

func (c *certificateRequestPatchHelper) SetIssued(bundle signer.PEMBundle) {
	c.patch.Certificate = bundle.ChainPEM
	if c.setCAOnCertificateRequest {
		c.patch.CA = bundle.CAPEM
	}
	message, _ := c.setCondition(
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionTrue,
		cmapi.CertificateRequestReasonIssued,
		"Succeeded signing the CertificateRequest",
	)
	c.eventRecorder.Event(c.readOnlyObj, corev1.EventTypeNormal, eventRequestIssued, message)
}

func (c *certificateRequestPatchHelper) Patch() (client.Object, client.Patch, error) {
	cr, patch, err := ssaclient.GenerateCertificateRequestStatusPatch(
		c.readOnlyObj.Name,
		c.readOnlyObj.Namespace,
		c.patch,
	)
	return &cr, patch, err
}

func (c *certificateRequestPatchHelper) CertificateRequestPatch() *cmapi.CertificateRequestStatus {
	return c.patch
}
