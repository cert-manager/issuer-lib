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

import "time"

// PendingError should be returned if we are certain that we will converge to a
// successful result or another type of error in a finite amount of time by
// just retrying the same operation.
//
// It can be used to circumvent the MaxRetryDuration
// check, which is useful for example when the signer is waiting for an async
// answer from an external service that is indicating that the request is still
// being processed.
//
// > This error should be returned only by the Sign function.
type PendingError struct {
	Err error

	// RequeueAfter can be used to specify how long to wait before retrying. By default
	// we wait for 1s before retrying.
	RequeueAfter time.Duration
}

var _ error = PendingError{}

func (ve PendingError) Unwrap() error {
	return ve.Err
}

func (ve PendingError) Error() string {
	return ve.Err.Error()
}
