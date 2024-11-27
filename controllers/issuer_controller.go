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
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/kubeutil"
	"github.com/cert-manager/issuer-lib/internal/ssaclient"
)

const (
	eventIssuerChecked        = "Checked"
	eventIssuerRetryableError = "RetryableError"
	eventIssuerPermanentError = "PermanentError"
)

// IssuerReconciler reconciles a TestIssuer object
type IssuerReconciler struct {
	ForObject v1alpha1.Issuer

	FieldOwner  string
	EventSource kubeutil.EventSource

	// Client is a controller-runtime client used to get and set K8S API resources
	client.Client
	// Check connects to a CA and checks if it is available
	signer.Check
	// IgnoreIssuer is an optional function that can prevent the issuer controllers from
	// reconciling an issuer resource.
	signer.IgnoreIssuer

	// EventRecorder is used for creating Kubernetes events on resources.
	EventRecorder record.EventRecorder

	// Clock is used to mock condition transition times in tests.
	Clock clock.PassiveClock

	// PreSetupWithManager is an optional function that can be used to perform
	// additional setup before the controller is built and registered with the
	// manager.
	PreSetupWithManager func(context.Context, schema.GroupVersionKind, ctrl.Manager, *builder.Builder) error

	// PostSetupWithManager is an optional function that can be used to perform
	// additional setup after the controller is built and registered with the
	// manager.
	PostSetupWithManager func(context.Context, schema.GroupVersionKind, ctrl.Manager, controller.Controller) error
}

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, returnedError error) {
	logger := log.FromContext(ctx).WithName("Reconcile")

	logger.V(2).Info("Starting reconcile loop", "name", req.Name, "namespace", req.Namespace)

	// The error returned by `reconcileStatusPatch` is meant for controller-runtime,
	// not for us. That's why we aren't checking `reconcileError != nil` .
	result, issuerStatusPatch, reconcileError := r.reconcileStatusPatch(logger, ctx, req)

	logger.V(2).Info("Got StatusPatch result", "result", result, "patch", issuerStatusPatch, "error", reconcileError)
	if issuerStatusPatch != nil {
		cr, patch, err := ssaclient.GenerateIssuerStatusPatch(r.ForObject, req.Name, req.Namespace, issuerStatusPatch)
		if err != nil {
			return ctrl.Result{}, utilerrors.NewAggregate([]error{err, reconcileError})
		}

		if err := r.Client.Status().Patch(ctx, cr, patch, &client.SubResourcePatchOptions{
			PatchOptions: client.PatchOptions{
				FieldManager: r.FieldOwner,
				Force:        ptr.To(true),
			},
		}); err != nil {
			if !apierrors.IsNotFound(err) {
				return ctrl.Result{}, utilerrors.NewAggregate([]error{err, reconcileError})
			}

			logger.V(1).Info("Not found. Ignoring.")
		}
	}

	return result, reconcileError
}

// reconcileStatusPatch is responsible for reconciling the issuer. It will return the
// result and reconcileError to be returned by the Reconcile function. It also returns
// an issuerStatusPatch that the Reconcile function will apply to the issuer's status.
// This function is split out from the Reconcile function to allow for easier testing.
//
// The error returned by `reconcileStatusPatch` is meant for controller-runtime,
// not for the caller. The caller must not check the error (i.e., they must not
// do `if err != nil...`).
func (r *IssuerReconciler) reconcileStatusPatch(
	logger logr.Logger,
	ctx context.Context,
	req ctrl.Request,
) (result ctrl.Result, issuerStatusPatch *v1alpha1.IssuerStatus, reconcileError error) { // nolint:unparam
	// Get the ClusterIssuer
	issuer := r.ForObject.DeepCopyObject().(v1alpha1.Issuer)
	forObjectGvk := r.ForObject.GetObjectKind().GroupVersionKind()
	// calling IsInvalidated early to make sure the map is always cleared
	reportedError := r.EventSource.HasReportedError(forObjectGvk, req.NamespacedName)

	if err := r.Client.Get(ctx, req.NamespacedName, issuer); err != nil && apierrors.IsNotFound(err) {
		logger.V(1).Info("Issuer not found. Ignoring.")
		return result, nil, nil // done
	} else if err != nil {
		return result, nil, fmt.Errorf("unexpected get error: %v", err) // requeue with backoff
	}

	readyCondition := conditions.GetIssuerStatusCondition(issuer.GetConditions(), v1alpha1.IssuerConditionTypeReady)

	// Ignore Issuer if it is already permanently Failed
	isFailed := (readyCondition != nil) &&
		(readyCondition.Status == metav1.ConditionFalse) &&
		(readyCondition.Reason == v1alpha1.IssuerConditionReasonFailed) &&
		(readyCondition.ObservedGeneration >= issuer.GetGeneration())
	if isFailed {
		logger.V(1).Info("Issuer is Failed Permanently. Ignoring.")
		return result, nil, nil // done
	}

	if r.IgnoreIssuer != nil {
		ignore, err := r.IgnoreIssuer(ctx, issuer)
		if err != nil {
			return result, nil, fmt.Errorf("failed to check if issuer should be ignored: %v", err) // requeue with backoff
		}
		if ignore {
			logger.V(1).Info("IgnoreIssuer() returned true. Ignoring.")
			return result, nil, nil // done
		}
	}

	// We now have a Issuer that belongs to us so we are responsible
	// for updating its Status.
	issuerStatusPatch = &v1alpha1.IssuerStatus{}

	setReadyCondition := func(
		status metav1.ConditionStatus,
		reason, message string,
	) string {
		condition, _ := conditions.SetIssuerStatusCondition(
			r.Clock,
			issuer.GetConditions(),
			&issuerStatusPatch.Conditions,
			issuer.GetGeneration(),
			v1alpha1.IssuerConditionTypeReady,
			status, reason, message,
		)
		return condition.Message
	}

	// Add a Ready condition if one does not already exist. Set initial Status
	// to Unknown.
	if readyCondition == nil {
		logger.V(1).Info("Initializing Ready condition")
		setReadyCondition(
			metav1.ConditionUnknown,
			v1alpha1.IssuerConditionReasonInitializing,
			fmt.Sprintf("%s has started reconciling this Issuer", r.FieldOwner),
		)
		// To continue reconciling this Issuer, we must re-run the reconcile loop
		// after adding the Unknown Ready condition. This update will trigger a
		// new reconcile loop, so we don't need to requeue here.
		return result, issuerStatusPatch, nil // apply patch, done
	}

	var err error
	if (readyCondition.Status == metav1.ConditionTrue) && (reportedError != nil) {
		// We received an error from a Certificaterequest while our current status is Ready,
		// update the ready state of the issuer to reflect the error.
		err = reportedError
	} else {
		err = r.Check(log.IntoContext(ctx, logger), issuer)
	}
	if err == nil {
		logger.V(1).Info("Successfully finished the reconciliation.")
		message := setReadyCondition(
			metav1.ConditionTrue,
			v1alpha1.IssuerConditionReasonChecked,
			"Succeeded checking the issuer",
		)
		r.EventRecorder.Event(issuer, corev1.EventTypeNormal, eventIssuerChecked, message)

		return result, issuerStatusPatch, nil // apply patch, done
	}

	isPermanentError := errors.As(err, &signer.PermanentError{})
	if isPermanentError {
		// fail permanently
		logger.V(1).Error(err, "Permanent Issuer error. Marking as failed.")
		message := setReadyCondition(
			metav1.ConditionFalse,
			v1alpha1.IssuerConditionReasonFailed,
			fmt.Sprintf("Failed permanently: %s", err),
		)
		r.EventRecorder.Event(issuer, corev1.EventTypeWarning, eventIssuerPermanentError, message)
		return result, issuerStatusPatch, reconcile.TerminalError(err) // apply patch, done
	} else {
		// retry
		logger.V(1).Error(err, "Retryable Issuer error.")
		message := setReadyCondition(
			metav1.ConditionFalse,
			v1alpha1.IssuerConditionReasonPending,
			fmt.Sprintf("Not ready yet: %s", err),
		)
		r.EventRecorder.Event(issuer, corev1.EventTypeWarning, eventIssuerRetryableError, message)
		return result, issuerStatusPatch, err // apply patch, requeue with backoff
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *IssuerReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := kubeutil.SetGroupVersionKind(mgr.GetScheme(), r.ForObject); err != nil {
		return err
	}
	forObjectGvk := r.ForObject.GetObjectKind().GroupVersionKind()

	build := ctrl.NewControllerManagedBy(mgr).
		For(
			r.ForObject,
			// we are only interested in changes to the .Spec part of the issuer
			// this also prevents us to get in fast reconcile loop when setting the
			// status to Pending causing the resource to update, while we only want
			// to re-reconcile with backoff/ when a resource becomes available.
			builder.WithPredicates(
				predicate.ResourceVersionChangedPredicate{},
				IssuerPredicate{},
			),
		).
		WatchesRawSource(r.EventSource.AddConsumer(forObjectGvk))

	if r.PreSetupWithManager != nil {
		err := r.PreSetupWithManager(ctx, forObjectGvk, mgr, build)
		r.PreSetupWithManager = nil // free setup function
		if err != nil {
			return err
		}
	}

	if controller, err := build.Build(r); err != nil {
		return err
	} else if r.PostSetupWithManager != nil {
		err := r.PostSetupWithManager(ctx, forObjectGvk, mgr, controller)
		r.PostSetupWithManager = nil // free setup function
		return err
	}
	return nil
}
