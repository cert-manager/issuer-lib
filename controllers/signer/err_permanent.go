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

// PermanentError is returned if it is impossible for the resource to
// get in a Ready state without being changed. It should not be used
// if there is any way to fix the error by altering the environment/
// other resources. The client should not try again after receiving
// this error.
//
// For the Check function, this error is useful when we detected an
// invalid configuration/ setting in the Issuer or ClusterIssuer resource.
// This should only happen very rarely, because of webhook validation.
//
// For the Sign function, this error is useful when we detected an
// error that will only get resolved by creating a new CertificateRequest,
// for example when it is required to craft a new CSR.
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
