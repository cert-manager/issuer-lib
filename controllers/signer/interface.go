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
	"context"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
)

type Sign func(ctx context.Context, cr CertificateRequestObject, issuerObject v1alpha1.Issuer) SignResult
type Check func(ctx context.Context, issuerObject v1alpha1.Issuer) error

// IgnoreIssuer is an optional function that can prevent the issuer controllers from
// reconciling an issuer resource. By default, the controllers will reconcile all
// issuer resources that match the owned types.
// This function will be called by the issuer reconcile loops for each type that matches
// the owned types. If the function returns true, the controller will not reconcile the
// issuer resource.
type IgnoreIssuer func(
	ctx context.Context,
	issuerObject v1alpha1.Issuer,
) (bool, error)

// IgnoreCertificateRequest is an optional function that can prevent the CertificateRequest
// and Kubernetes CSR controllers from reconciling a CertificateRequest resource. By default,
// the controllers will reconcile all CertificateRequest resources that match the issuerRef type.
// This function will be called by the CertificateRequest reconcile loop and the Kubernetes CSR
// reconcile loop for each type that matches the issuerRef type. If the function returns true,
// the controller will not reconcile the CertificateRequest resource.
type IgnoreCertificateRequest func(
	ctx context.Context,
	cr CertificateRequestObject,
	issuerGvk schema.GroupVersionKind,
	issuerName types.NamespacedName,
) (bool, error)
