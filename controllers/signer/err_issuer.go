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

// IssuerError is thrown by the CertificateRequest controller
// to indicate that er was an error in the issuer part of the
// reconcile process, and that the issuer's reconcile function
// should be retriggered.
//
// This error is useful to indicate that the Sign function got
// an error for an action that should have been checked by the
// Check function, and that has appeared after the Check function
// has been called.
//
// > This error should be returned only by the Sign function.
type IssuerError struct {
	Err error
}

var _ error = IssuerError{}

func (ve IssuerError) Unwrap() error {
	return ve.Err
}

func (ve IssuerError) Error() string {
	return ve.Err.Error()
}
