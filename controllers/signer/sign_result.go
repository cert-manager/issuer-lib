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

package signer

import (
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SignResult represents the result of a Sign operation, can be either a success
// or an error.
type SignResult struct {
	// SignResult must be constructed using either SignSuccess or SignError,
	// not by direct struct literal construction. This field is used to enforce that.
	wasProperlyConstructed bool

	// The first certificate in the ChainPEM chain is the leaf certificate, and the
	// last certificate in the chain is the highest level non-self-signed certificate.
	chainPEM []byte

	// The CAPEM certificate is our best guess at the CA that issued the leaf.
	// IMPORTANT: the CAPEM certificate is only used when the SetCAOnCertificateRequest
	// option is enabled in the controller. This option exists for backwards
	// compatibility only. Use of the CA field and the `ca.crt` field in the
	// resulting Secret is discouraged; the CA should instead be provisioned
	// separately (for example, using trust-manager).
	caPEM []byte

	// Any additional conditions to set on the CertificateRequest or
	// CertificateSigningRequest resource. These must be supplied on every
	// reconciliation (even when signing fails); otherwise the conditions will be
	// removed.
	//
	// - Type: type of condition in CamelCase or in foo.example.com/CamelCase
	//   Should not be Ready, as that is managed by the controller instead.
	// - Status: the condition status, one of True, False, or Unknown.
	// - Reason: a programmatic identifier indicating why the condition last
	//   transitioned. Producers of specific condition types may define expected
	//   values and meanings for this field. The value should be a CamelCase
	//   string and may not be empty.
	// - Message: a human-readable message describing the transition. This may
	//   be empty.
	//
	// All other fields of the condition are ignored and will be set by the
	// controller automatically.
	otherConditions []metav1.Condition

	// An error that occurred during signing.
	//
	// Can be a PermanentError, PendingError, IssuerError, or any other error.
	// - If nil, signing was successful.
	// - PermanentError is returned when it is impossible for the resource to
	//   become Ready without changing the resource itself. It must not be used
	//   when the issue can be resolved by modifying the environment or other
	//   resources. The controller should not retry after receiving this error.
	//   For the Sign function, return this when the problem can only be
	//   resolved by creating a new CertificateRequest (for example, when a new
	//   CSR must be generated).
	// - PendingError should be returned when retrying the same operation is
	//   expected to result in success or another error within a finite time.
	//   It can be used to bypass the MaxRetryDuration check, for example when
	//   the signer is waiting for an asynchronous response from an external
	//   service indicating the request is still being processed.
	// - IssuerError is returned to indicate an error in the issuer part of the
	//   reconcile process and that the issuer's reconcile function should be
	//   retried. It is useful when the Sign function encounters an error for an
	//   action that should have been handled by the Check function, and which
	//   surfaced after Check had already succeeded.
	// - Any other error indicates a transient error that might be resolved by
	//   retrying the operation. The controller will retry as long as the
	//   MaxRetryDuration has not been exceeded since creation of the
	//   CertificateRequest/CertificateSigningRequest.
	err error
}

type SignSucessOption interface {
	applySuccessResult(*SignResult)
}

// Signing was successful.
//
// The first certificate in the chainPEM chain is the leaf certificate, and the
// last certificate in the chain is the highest level non-self-signed certificate.
func SignSuccess(chainPEM []byte, opts ...SignSucessOption) SignResult {
	result := SignResult{
		wasProperlyConstructed: true,
		chainPEM:               chainPEM,
	}

	for _, opt := range opts {
		opt.applySuccessResult(&result)
	}

	return result
}

type SignErrorOption interface {
	applyErrorResult(*SignResult)
}

// An error that occurred during signing.
//
// Can be a PermanentError, PendingError, IssuerError, or any other error.
//   - If nil, signing was successful.
//   - PermanentError is returned when it is impossible for the resource to
//     become Ready without changing the resource itself. It must not be used
//     when the issue can be resolved by modifying the environment or other
//     resources. The controller should not retry after receiving this error.
//     For the Sign function, return this when the problem can only be
//     resolved by creating a new CertificateRequest (for example, when a new
//     CSR must be generated).
//   - PendingError should be returned when retrying the same operation is
//     expected to result in success or another error within a finite time.
//     It can be used to bypass the MaxRetryDuration check, for example when
//     the signer is waiting for an asynchronous response from an external
//     service indicating the request is still being processed.
//   - IssuerError is returned to indicate an error in the issuer part of the
//     reconcile process and that the issuer's reconcile function should be
//     retried. It is useful when the Sign function encounters an error for an
//     action that should have been handled by the Check function, and which
//     surfaced after Check had already succeeded.
//   - Any other error indicates a transient error that might be resolved by
//     retrying the operation. The controller will retry as long as the
//     MaxRetryDuration has not been exceeded since creation of the
//     CertificateRequest/CertificateSigningRequest.
func SignError(err error, opts ...SignErrorOption) SignResult {
	result := SignResult{
		wasProperlyConstructed: true,
		err:                    err,
	}

	for _, opt := range opts {
		opt.applyErrorResult(&result)
	}

	return result
}

type funcResultOption func(*SignResult)

func (f funcResultOption) applySuccessResult(r *SignResult) {
	f(r)
}

func (f funcResultOption) applyErrorResult(r *SignResult) {
	f(r)
}

// Any additional conditions to set on the CertificateRequest or
// CertificateSigningRequest resource. These must be supplied on every
// reconciliation (even when signing fails); otherwise the conditions will be
// removed.
//
//   - Status: the condition status, one of True, False, or Unknown.
//   - Reason: a programmatic identifier indicating why the condition last
//     transitioned. Producers of specific condition types may define expected
//     values and meanings for this field. The value should be a CamelCase
//     string and may not be empty.
//   - Message: a human-readable message describing the transition. This may
//     be empty.
//
// All other fields of the condition are ignored and will be set by the
// controller automatically.
func WithExtraConditions(conditions ...metav1.Condition) interface {
	SignSucessOption
	SignErrorOption
} {
	return funcResultOption(func(r *SignResult) {
		r.otherConditions = append(r.otherConditions, conditions...)
	})
}

// The CAPEM certificate is our best guess at the CA that issued the leaf.
// IMPORTANT: the CAPEM certificate is only used when the SetCAOnCertificateRequest
// option is enabled in the controller. This option exists for backwards
// compatibility only. Use of the CA field and the `ca.crt` field in the
// resulting Secret is discouraged; the CA should instead be provisioned
// separately (for example, using trust-manager).
func WithCA(caPEM []byte) SignSucessOption {
	return funcResultOption(func(r *SignResult) {
		r.caPEM = caPEM
	})
}

// INTERNAL USE ONLY - do not use outside of this package (this will break in future releases)
// Unpack extracts all data from the SignResult.
func (sr SignResult) Unpack() (pki.PEMBundle, []metav1.Condition, error) {
	if !sr.wasProperlyConstructed {
		panic("PROGRAMMER ERROR: SignResult must be constructed using either SignSuccess or SignError")
	}

	return pki.PEMBundle{
		ChainPEM: sr.chainPEM,
		CAPEM:    sr.caPEM,
	}, sr.otherConditions, sr.err
}
