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
	"maps"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/kubeutil"
)

type CombinedController struct {
	// IssuerTypes is a map of empty namespaced issuer objects, each supported issuer type
	// should have its own entry. The key should be the GroupResource for that issuer, the
	// resource being the plural lowercase resource name.
	IssuerTypes map[schema.GroupResource]v1alpha1.Issuer
	// ClusterIssuerTypes is a map of empty cluster-scoped issuer objects, each supported issuer type
	// should have its own entry. The key should be the GroupResource for that issuer, the
	// resource being the plural lowercase resource name.
	ClusterIssuerTypes map[schema.GroupResource]v1alpha1.Issuer

	FieldOwner string

	MaxRetryDuration time.Duration

	// Check connects to a CA and checks if it is available
	signer.Check
	// Sign connects to a CA and returns a signed certificate for the supplied CertificateRequest.
	signer.Sign

	// IgnoreCertificateRequest is an optional function that can prevent the CertificateRequest
	// and Kubernetes CSR controllers from reconciling a CertificateRequest resource.
	signer.IgnoreCertificateRequest
	// IgnoreIssuer is an optional function that can prevent the issuer controllers from
	// reconciling an issuer resource.
	signer.IgnoreIssuer

	// EventRecorder is used for creating Kubernetes events on resources.
	EventRecorder record.EventRecorder

	// Clock is used to mock condition transition times in tests.
	Clock clock.PassiveClock

	// SetCAOnCertificateRequest is used to enable setting the CA status field on
	// the CertificateRequest resource. This is disabled by default.
	// Deprecated: this option is for backwards compatibility only. The use of
	// ca.crt is discouraged. Instead, the CA certificate should be provided
	// separately using a tool such as trust-manager.
	SetCAOnCertificateRequest bool

	// DisableCertificateRequestController is used to disable the CertificateRequest
	// controller. This controller is enabled by default.
	// You should only disable this controller if you eg. don't want to rely on the cert-manager
	// CRDs to be installed.
	// Note: in the future, we might remove this option and always enable the CertificateRequest
	// controller.
	DisableCertificateRequestController bool

	// DisableKubernetesCSRController is used to disable the Kubernetes CSR controller.
	// This controller is enabled by default.
	// You should only disable this controller if you really don't want to support signing
	// Kubernetes CSRs.
	// Note: in the future, we might remove this option and always enable the Kubernetes CSR
	// controller.
	DisableKubernetesCSRController bool

	// PreSetupWithManager is an optional function that can be used to perform
	// additional setup before the controller is built and registered with the
	// manager.
	PreSetupWithManager func(context.Context, schema.GroupVersionKind, ctrl.Manager, *builder.Builder) error

	// PostSetupWithManager is an optional function that can be used to perform
	// additional setup after the controller is built and registered with the
	// manager.
	PostSetupWithManager func(context.Context, schema.GroupVersionKind, ctrl.Manager, controller.Controller) error
}

func (r *CombinedController) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	var err error
	cl := mgr.GetClient()
	eventSource := kubeutil.NewEventStore()

	if r.Clock == nil {
		r.Clock = clock.RealClock{}
	}

	for _, issuerType := range slices.Concat(
		slices.Collect(maps.Values(r.IssuerTypes)),
		slices.Collect(maps.Values(r.ClusterIssuerTypes)),
	) {
		if err = (&IssuerReconciler{
			ForObject: issuerType,

			FieldOwner:  r.FieldOwner,
			EventSource: eventSource,

			Client:        cl,
			Check:         r.Check,
			IgnoreIssuer:  r.IgnoreIssuer,
			EventRecorder: r.EventRecorder,
			Clock:         r.Clock,

			PreSetupWithManager:  r.PreSetupWithManager,
			PostSetupWithManager: r.PostSetupWithManager,
		}).SetupWithManager(ctx, mgr); err != nil {
			return fmt.Errorf("%T: %w", issuerType, err)
		}
	}

	if r.DisableCertificateRequestController && r.DisableKubernetesCSRController {
		return fmt.Errorf("both CertificateRequest and Kubernetes CSR controllers are disabled, must enable at least one")
	}

	if !r.DisableCertificateRequestController {
		if err = (&CertificateRequestReconciler{
			RequestController: RequestController{
				IssuerTypes:        r.IssuerTypes,
				ClusterIssuerTypes: r.ClusterIssuerTypes,

				FieldOwner:       r.FieldOwner,
				MaxRetryDuration: r.MaxRetryDuration,
				EventSource:      eventSource,

				Client:                   cl,
				Sign:                     r.Sign,
				IgnoreCertificateRequest: r.IgnoreCertificateRequest,
				EventRecorder:            r.EventRecorder,
				Clock:                    r.Clock,

				PreSetupWithManager:  r.PreSetupWithManager,
				PostSetupWithManager: r.PostSetupWithManager,
			},

			SetCAOnCertificateRequest: r.SetCAOnCertificateRequest,
		}).SetupWithManager(ctx, mgr); err != nil {
			return fmt.Errorf("CertificateRequestReconciler: %w", err)
		}
	}

	if !r.DisableKubernetesCSRController {
		if err = (&CertificateSigningRequestReconciler{
			RequestController: RequestController{
				IssuerTypes:        r.IssuerTypes,
				ClusterIssuerTypes: r.ClusterIssuerTypes,

				FieldOwner:       r.FieldOwner,
				MaxRetryDuration: r.MaxRetryDuration,
				EventSource:      eventSource,

				Client:                   cl,
				Sign:                     r.Sign,
				IgnoreCertificateRequest: r.IgnoreCertificateRequest,
				EventRecorder:            r.EventRecorder,
				Clock:                    r.Clock,

				PreSetupWithManager:  r.PreSetupWithManager,
				PostSetupWithManager: r.PostSetupWithManager,
			},
		}).SetupWithManager(ctx, mgr); err != nil {
			return fmt.Errorf("CertificateRequestReconciler: %w", err)
		}
	}

	return nil
}
