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
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/kubeutil"
)

type CombinedController struct {
	IssuerTypes        []v1alpha1.Issuer
	ClusterIssuerTypes []v1alpha1.Issuer

	FieldOwner string

	MaxRetryDuration time.Duration

	// Check connects to a CA and checks if it is available
	signer.Check
	// Sign connects to a CA and returns a signed certificate for the supplied CertificateRequest.
	signer.Sign

	// EventRecorder is used for creating Kubernetes events on resources.
	EventRecorder record.EventRecorder

	// Clock is used to mock condition transition times in tests.
	Clock clock.PassiveClock

	PostSetupWithManager func(context.Context, schema.GroupVersionKind, ctrl.Manager, controller.Controller) error
}

func (r *CombinedController) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	var err error
	cl := mgr.GetClient()
	eventSource := kubeutil.NewEventStore()

	if r.Clock == nil {
		r.Clock = clock.RealClock{}
	}

	for _, issuerType := range append(r.IssuerTypes, r.ClusterIssuerTypes...) {
		if err = (&IssuerReconciler{
			ForObject: issuerType,

			FieldOwner:  r.FieldOwner,
			EventSource: eventSource,

			Client:        cl,
			Check:         r.Check,
			EventRecorder: r.EventRecorder,
			Clock:         r.Clock,

			PostSetupWithManager: r.PostSetupWithManager,
		}).SetupWithManager(ctx, mgr); err != nil {
			return fmt.Errorf("%T: %w", issuerType, err)
		}
	}

	if err = (&CertificateRequestReconciler{
		IssuerTypes:        r.IssuerTypes,
		ClusterIssuerTypes: r.ClusterIssuerTypes,

		FieldOwner:       r.FieldOwner,
		MaxRetryDuration: r.MaxRetryDuration,
		EventSource:      eventSource,

		Client:        cl,
		Sign:          r.Sign,
		EventRecorder: r.EventRecorder,
		Clock:         r.Clock,

		PostSetupWithManager: r.PostSetupWithManager,
	}).SetupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("CertificateRequestReconciler: %w", err)
	}

	return nil
}
