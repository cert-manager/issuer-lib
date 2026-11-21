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

	authzv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
)

// CertificateSigningRequestReconciler reconciles a CertificateSigningRequest object
type CertificateSigningRequestReconciler struct {
	RequestController

	EnableNamespacedIssuerCSR bool

	// Allows callers to tune workers, rate limiter, panic recovery, etc.
	ControllerOptions controller.Options
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
		if issuerTypeIdentifier != issuerType.Type.GetIssuerTypeIdentifier() {
			continue
		}

		issuerObject := issuerType.Type.DeepCopyObject().(v1alpha1.Issuer)

		if !issuerType.IsNamespaced {
			return issuerObject, types.NamespacedName{
				Name: issuerIdentifier,
			}, nil
		}

		if !r.EnableNamespacedIssuerCSR {
			return nil, types.NamespacedName{}, fmt.Errorf("invalid SignerName, %q is a namespaced issuer type, namespaced issuers are not supported for Kubernetes CSRs", issuerTypeIdentifier)
		}

		ns, name, ok := strings.Cut(issuerIdentifier, ".")

		if !ok || ns == "" || name == "" {
			return nil, types.NamespacedName{}, fmt.Errorf("invalid signer name, should have format %s/<namespace>.<name>: %q", issuerTypeIdentifier, csr.Spec.SignerName)
		}

		return issuerObject, types.NamespacedName{
			Namespace: ns,
			Name:      name,
		}, nil
	}

	return nil, types.NamespacedName{}, fmt.Errorf("no issuer found for signer name: %q", csr.Spec.SignerName)
}

func (r *CertificateSigningRequestReconciler) authorizeRequest(ctx context.Context, requestObject client.Object, issuerObj v1alpha1.Issuer, issuerName types.NamespacedName) error {
	if issuerName.Namespace == "" {
		return nil
	}

	csr := requestObject.(*certificatesv1.CertificateSigningRequest)

	extra := make(map[string]authzv1.ExtraValue)
	for k, v := range csr.Spec.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}

	group := issuerObj.GetObjectKind().GroupVersionKind().Group

	for _, name := range []string{issuerName.Name, "*"} {
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:   csr.Spec.Username,
				Groups: csr.Spec.Groups,
				Extra:  extra,
				UID:    csr.Spec.UID,

				ResourceAttributes: &authzv1.ResourceAttributes{
					Group:     group,
					Resource:  "signers",
					Verb:      "reference",
					Namespace: issuerName.Namespace,
					Name:      name,
					Version:   "*",
				},
			},
		}

		if err := r.Client.Create(ctx, sar); err != nil {
			return fmt.Errorf("failed to create SubjectAccessReview for signer %q: %w", csr.Spec.SignerName, err)
		}

		if sar.Status.Allowed {
			return nil
		}
	}

	return signer.RequestDeniedError{
		Reason:  "DeniedReference",
		Message: fmt.Sprintf("Requester may not reference Namespaced Issuer %s/%s", issuerName.Namespace, issuerName.Name),
	}
}

func (r *CertificateSigningRequestReconciler) Init() *CertificateSigningRequestReconciler {
	var authorize AuthorizeRequest
	if r.EnableNamespacedIssuerCSR {
		authorize = r.authorizeRequest
	}

	r.RequestController.Init(
		&certificatesv1.CertificateSigningRequest{},
		CertificateSigningRequestPredicate{},
		r.matchIssuerType,
		func(o client.Object) RequestObjectHelper {
			return &certificatesigningRequestObjectHelper{
				readOnlyObj: o.(*certificatesv1.CertificateSigningRequest),
			}
		},
		authorize,
	)

	return r
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateSigningRequestReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := setupCertificateSigningRequestReconcilerScheme(mgr.GetScheme()); err != nil {
		return err
	}

	r.Init()

	// Propagate controller-runtime options to the underlying RequestController
	r.RequestController.ControllerOptions = r.ControllerOptions

	return r.RequestController.SetupWithManager(
		ctx,
		mgr,
	)
}

func setupCertificateSigningRequestReconcilerScheme(scheme *runtime.Scheme) error {
	if err := certificatesv1.AddToScheme(scheme); err != nil {
		return err
	}
	return authzv1.AddToScheme(scheme)
}
