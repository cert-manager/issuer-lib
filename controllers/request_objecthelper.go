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
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/issuer-lib/controllers/signer"
)

const (
	eventRequestIssued    = "Issued"
	eventRequestRetryable = "Pending"

	eventRequestUnexpectedError = "UnexpectedError"
	eventRequestRetryableError  = "RetryableError"
	eventRequestPermanentError  = "PermanentError"

	eventRequestWaitingForIssuerExist = "WaitingForIssuerExist"
	eventRequestWaitingForIssuerReady = "WaitingForIssuerReady"
)

type RequestObjectHelper interface {
	IsApproved() bool
	IsDenied() bool
	IsReady() bool
	IsFailed() bool

	RequestObject() signer.CertificateRequestObject

	NewPatch(
		clock clock.PassiveClock,
		fieldOwner string,
		eventRecorder record.EventRecorder,
	) RequestPatchHelper
}

type RequestPatchHelper interface { //nolint:interfacebloat
	RequestPatch

	SetInitializing() (didInitialise bool)
	SetWaitingForIssuerExist(error)
	SetWaitingForIssuerReadyNoCondition()
	SetWaitingForIssuerReadyOutdated()
	SetWaitingForIssuerReadyNotReady(*metav1.Condition)
	SetCustomCondition(
		conditionType string,
		conditionStatus metav1.ConditionStatus,
		conditionReason string, conditionMessage string,
	) (didCustomConditionTransition bool)
	SetPending(reason string)
	SetRetryableError(error)
	SetPermanentError(error)
	SetUnexpectedError(error)
	SetIssued(signer.PEMBundle)
}

type RequestPatch interface {
	Patch() (client.Object, client.Patch, error)
}

type CertificateRequestPatch interface {
	CertificateRequestPatch() *cmapi.CertificateRequestStatus
}

type CertificateSigningRequestPatch interface {
	CertificateSigningRequestPatch() *certificatesv1.CertificateSigningRequestStatus
}
