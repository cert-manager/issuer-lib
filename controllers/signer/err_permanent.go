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

// PermanentError is returned when it is impossible for the resource to
// become Ready without changing the resource itself. It must not be used
// when the issue can be resolved by modifying the environment or other
// resources. The controller should not retry after receiving this error.
//
// For the Check function, this error is useful when we detected an
// invalid configuration/ setting in the Issuer or ClusterIssuer resource.
// This should only happen very rarely, because of webhook validation.
//
// For the Sign function, this error is useful when the problem can only be
// resolved by creating a new CertificateRequest (for example, when a new
// CSR must be generated).
//
// > This error should be returned by the Sign or Check function.
type PermanentError struct {
	Err error
}

var _ error = PermanentError{}

func (ve PermanentError) Unwrap() error {
	return ve.Err
}

func (ve PermanentError) Error() string {
	return ve.Err.Error()
}
