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

	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	RequestController

	// SetCAOnCertificateRequest is used to enable setting the CA status field on
	// the CertificateRequest resource. This is disabled by default.
	//
	// Deprecated: this option is for backwards compatibility only. The use of
	// ca.crt is discouraged. Instead, the CA certificate should be provided
	// separately using a tool such as trust-manager.
	SetCAOnCertificateRequest bool

	// Allows callers to tune workers, rate limiter, panic recovery, etc.
	ControllerOptions controller.Options
}

func (r *CertificateRequestReconciler) matchIssuerType(requestObject client.Object) (v1alpha1.Issuer, types.NamespacedName, error) {
	cr := requestObject.(*cmapi.CertificateRequest)

	if cr == nil {
		return nil, types.NamespacedName{}, fmt.Errorf("invalid reference, CertificateRequest is nil")
	}

	// cert-manager core does not default issuerRef.group or issuerRef.kind on
	// stored objects (the CRD has no defaults for issuerRef), yet users
	// routinely omit them. Core resolves an omitted group to "cert-manager.io"
	// and an omitted kind to "Issuer". For in-tree issuer types (see the
	// intree package) we must apply the same rules so that this controller
	// and core agree on which issuer a CertificateRequest refers to.
	//
	// The group default is unconditional, but the kind default only applies
	// to the cert-manager.io group: for third-party groups core has no
	// opinion, and issuer-lib keeps its behaviour of treating an empty kind
	// as a wildcard that matches the first registered type.
	group := cr.Spec.IssuerRef.Group
	if group == "" {
		group = certmanager.GroupName
	}

	// Search for matching issuer
	for _, issuerType := range r.AllIssuerTypes() {
		gvk := issuerType.Type.GetObjectKind().GroupVersionKind()

		if group != gvk.Group {
			continue
		}

		kind := cr.Spec.IssuerRef.Kind
		if kind == "" && gvk.Group == certmanager.GroupName {
			kind = cmapi.IssuerKind
		}

		if kind != "" && kind != gvk.Kind {
			continue
		}

		namespace := ""
		if issuerType.IsNamespaced {
			namespace = cr.Namespace
		}

		issuerObject := issuerType.Type.DeepCopyObject().(v1alpha1.Issuer)
		issuerName := types.NamespacedName{
			Name:      cr.Spec.IssuerRef.Name,
			Namespace: namespace,
		}
		return issuerObject, issuerName, nil
	}

	return nil, types.NamespacedName{}, fmt.Errorf("no issuer found for reference: [Group=%q, Kind=%q, Name=%q]", group, cr.Spec.IssuerRef.Kind, cr.Spec.IssuerRef.Name)
}

func (r *CertificateRequestReconciler) Init() *CertificateRequestReconciler {
	r.RequestController.Init(
		&cmapi.CertificateRequest{},
		CertificateRequestPredicate{},
		r.matchIssuerType,
		func(o client.Object) RequestObjectHelper {
			return &certificateRequestObjectHelper{
				readOnlyObj:               o.(*cmapi.CertificateRequest),
				setCAOnCertificateRequest: r.SetCAOnCertificateRequest,
			}
		},
	)

	return r
}

func (r *CertificateRequestReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := setupCertificateRequestReconcilerScheme(mgr.GetScheme()); err != nil {
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

func setupCertificateRequestReconcilerScheme(scheme *runtime.Scheme) error {
	return cmapi.AddToScheme(scheme)
}
