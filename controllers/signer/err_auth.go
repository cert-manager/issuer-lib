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

package signer

import "time"

// RequestDeniedError is returned by AuthorizeRequest to fail a request
// with a reason. This usually happens mostly after a SubjectAccessReview (SAR)
// where the user doesn't have access to actually reference the issuer.
type RequestDeniedError struct {
	Err error

	// RequeueAfter can be set to control how long to wait before retrying. By
	// default the controller waits 1s before retrying.
	RequeueAfter time.Duration

	Message string

	Reason string
}

var _ error = RequestDeniedError{}

func (rae RequestDeniedError) Unwrap() error {
	return rae.Err
}

func (rae RequestDeniedError) Error() string {
	if rae.Err != nil {
		return rae.Err.Error()
	}
	return rae.Message
}
