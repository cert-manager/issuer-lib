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
	"context"
	"fmt"
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
)

// CertificateSigningRequestReconciler reconciles a CertificateSigningRequest object
type CertificateSigningRequestReconciler struct {
	RequestController
}

// matchIssuerType returns the IssuerType and IssuerName that matches the
// signerName of the CertificateSigningRequest. If no match is found, an error
// is returned.
// The signerName of the CertificateSigningRequest should be in the format
// "<issuer-type-id>/<issuer-id>". The issuer-type-id is obtained from the
// GetIssuerTypeIdentifier function of the IssuerType.
// The issuer-id is "<name>" for a ClusterIssuer resource.
func (r *CertificateSigningRequestReconciler) matchIssuerType(requestObject client.Object) (v1alpha1.Issuer, types.NamespacedName, error) {
	csr := requestObject.(*certificatesv1.CertificateSigningRequest)

	if csr == nil {
		return nil, types.NamespacedName{}, fmt.Errorf("invalid signer name, should have format <issuer-type-id>/<issuer-id>")
	}

	split := strings.Split(csr.Spec.SignerName, "/")
	if len(split) != 2 {
		return nil, types.NamespacedName{}, fmt.Errorf("invalid signer name, should have format <issuer-type-id>/<issuer-id>: %q", csr.Spec.SignerName)
	}

	issuerTypeIdentifier := split[0]
	issuerIdentifier := split[1]

	// Search for matching issuer
	for _, issuerType := range r.AllIssuerTypes() {
		if issuerTypeIdentifier != issuerType.IssuerTypeIdentifier {
			continue
		}

		issuerObject := issuerType.Type.DeepCopyObject().(v1alpha1.Issuer)

		issuerName := types.NamespacedName{
			Name: issuerIdentifier,
		}

		if issuerType.IsNamespaced {
			return nil, types.NamespacedName{}, fmt.Errorf("invalid SignerName, %q is a namespaced issuer type, namespaced issuers are not supported for Kubernetes CSRs", issuerTypeIdentifier)
		}

		return issuerObject, issuerName, nil
	}

	return nil, types.NamespacedName{}, fmt.Errorf("no issuer found for signer name: %q", csr.Spec.SignerName)
}

func (r *CertificateSigningRequestReconciler) Init() *CertificateSigningRequestReconciler {
	r.RequestController.Init(
		&certificatesv1.CertificateSigningRequest{},
		CertificateSigningRequestPredicate{},
		r.matchIssuerType,
		func(o client.Object) RequestObjectHelper {
			return &certificatesigningRequestObjectHelper{
				readOnlyObj: o.(*certificatesv1.CertificateSigningRequest),
			}
		},
	)

	return r
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateSigningRequestReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := setupCertificateSigningRequestReconcilerScheme(mgr.GetScheme()); err != nil {
		return err
	}

	r.Init()

	return r.RequestController.SetupWithManager(
		ctx,
		mgr,
	)
}

func setupCertificateSigningRequestReconcilerScheme(scheme *runtime.Scheme) error {
	return certificatesv1.AddToScheme(scheme)
}
