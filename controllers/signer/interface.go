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

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
)

// PEMBundle includes the PEM encoded X.509 certificate chain and CA.
// The first certificate in the ChainPEM chain is the leaf certificate, and the
// last certificate in the chain is the highest level non-self-signed certificate.
// The CAPEM certificate is our best guess at the CA that issued the leaf.
// IMPORTANT: the CAPEM certificate is only used when the SetCAOnCertificateRequest
// option is enabled in the controller. This option exists for backwards compatibility
// only. Use of the CA field and the `ca.crt` field in the resulting Secret is
// discouraged; the CA should instead be provisioned separately (for example, using trust-manager).
type PEMBundle pki.PEMBundle

type Sign func(ctx context.Context, cr CertificateRequestObject, issuerObject v1alpha1.Issuer) (PEMBundle, error)
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
