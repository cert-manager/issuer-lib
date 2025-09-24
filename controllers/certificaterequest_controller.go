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

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	RequestController

	// SetCAOnCertificateRequest is used to enable setting the CA status field on
	// the CertificateRequest resource. This is disabled by default.
	// Deprecated: this option is for backwards compatibility only. The use of
	// ca.crt is discouraged. Instead, the CA certificate should be provided
	// separately using a tool such as trust-manager.
	SetCAOnCertificateRequest bool
}

func (r *CertificateRequestReconciler) matchIssuerType(requestObject client.Object) (v1alpha1.Issuer, types.NamespacedName, error) {
	cr := requestObject.(*cmapi.CertificateRequest)

	if cr == nil {
		return nil, types.NamespacedName{}, fmt.Errorf("invalid reference, CertificateRequest is nil")
	}

	// Search for matching issuer
	for _, issuerType := range r.AllIssuerTypes() {
		gvk := issuerType.Type.GetObjectKind().GroupVersionKind()

		if (cr.Spec.IssuerRef.Group != gvk.Group) ||
			(cr.Spec.IssuerRef.Kind != "" && cr.Spec.IssuerRef.Kind != gvk.Kind) {
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

	return nil, types.NamespacedName{}, fmt.Errorf("no issuer found for reference: [Group=%q, Kind=%q, Name=%q]", cr.Spec.IssuerRef.Group, cr.Spec.IssuerRef.Kind, cr.Spec.IssuerRef.Name)
}

func (r *CertificateRequestReconciler) fetchCMIssuers(ctx context.Context, requestObject client.Object) (v1alpha1.Issuer, types.NamespacedName, error) {
	cr := requestObject.(*cmapi.CertificateRequest)

	if cr == nil {
		return nil, types.NamespacedName{}, fmt.Errorf("invalid reference, CertificateRequest is nil")
	}

	// If AllIssuerTypes are empty or doesn't match anything given then return clusterissuer/issuer as issuers
	if cr.Spec.IssuerRef.Kind == cmapi.IssuerKind {
		issuerName := &types.NamespacedName{
			Name:      cr.Spec.IssuerRef.Name,
			Namespace: cr.Namespace,
		}

		var iss *cmapi.Issuer
		err := r.Client.Get(ctx, *issuerName, iss)
		if err != nil {
			return nil, types.NamespacedName{}, err
		}

		nativeIssuer := new(v1alpha1.NativeIssuer)
		nativeIss := nativeIssuer.DeepCopyObject().(*v1alpha1.NativeIssuer)
		nativeIss.Issuer = *iss

		return nativeIssuer, *issuerName, nil
	}

	if cr.Spec.IssuerRef.Kind == cmapi.ClusterIssuerKind {
		var clusterIssuersList *cmapi.ClusterIssuerList
		err := r.Client.List(ctx, clusterIssuersList)
		if err != nil {
			return nil, types.NamespacedName{}, err
		}

		var clusterIssuer cmapi.ClusterIssuer
		for _, cli := range clusterIssuersList.Items {
			if strings.EqualFold(cli.Name, cr.Spec.IssuerRef.Name) {
				clusterIssuer = cli
			}
		}

		nativeClusterIsser := new(v1alpha1.ClusterNativeIssuer)
		nativeClusterIss := nativeClusterIsser.DeepCopyObject().(*v1alpha1.ClusterNativeIssuer)
		nativeClusterIss.ClusterIssuer = clusterIssuer

		return nativeClusterIss, types.NamespacedName{}, nil
	}

	return nil, types.NamespacedName{}, fmt.Errorf("no cm native issuers found for reference: [Group=%q, Kind=%q, Name=%q]", cr.Spec.IssuerRef.Group, cr.Spec.IssuerRef.Kind, cr.Spec.IssuerRef.Name)
}

func (r *CertificateRequestReconciler) Init() *CertificateRequestReconciler {
	r.RequestController.Init(
		&cmapi.CertificateRequest{},
		CertificateRequestPredicate{},
		r.matchIssuerType,
		r.matchNativeIssuerType,
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

	return r.RequestController.SetupWithManager(
		ctx,
		mgr,
	)
}

func setupCertificateRequestReconcilerScheme(scheme *runtime.Scheme) error {
	return cmapi.AddToScheme(scheme)
}
