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
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/kubeutil"
	"github.com/cert-manager/issuer-lib/internal/ssaclient"
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	IssuerTypes        []v1alpha1.Issuer
	ClusterIssuerTypes []v1alpha1.Issuer

	FieldOwner       string
	MaxRetryDuration time.Duration
	EventSource      kubeutil.EventSource

	// Client is a controller-runtime client used to get and set K8S API resources
	client.Client
	// Sign connects to a CA and returns a signed certificate for the supplied CertificateRequest.
	signer.Sign
	// IgnoreCertificateRequest is an optional function that can prevent the CertificateRequest
	// and Kubernetes CSR controllers from reconciling a CertificateRequest resource.
	signer.IgnoreCertificateRequest

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

	PostSetupWithManager func(context.Context, schema.GroupVersionKind, ctrl.Manager, controller.Controller) error
}

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, returnedError error) {
	logger := log.FromContext(ctx).WithName("Reconcile")

	logger.V(2).Info("Starting reconcile loop", "name", req.Name, "namespace", req.Namespace)

	result, crStatusPatch, returnedError := r.reconcileStatusPatch(logger, ctx, req)
	logger.V(2).Info("Got StatusPatch result", "result", result, "patch", crStatusPatch, "error", returnedError)
	if crStatusPatch != nil {
		cr, patch, err := ssaclient.GenerateCertificateRequestStatusPatch(req.Name, req.Namespace, crStatusPatch)
		if err != nil {
			return ctrl.Result{}, utilerrors.NewAggregate([]error{err, returnedError})
		}

		if err := r.Client.Status().Patch(ctx, &cr, patch, &client.SubResourcePatchOptions{
			PatchOptions: client.PatchOptions{
				FieldManager: r.FieldOwner,
				Force:        pointer.Bool(true),
			},
		}); err != nil {
			if err := client.IgnoreNotFound(err); err != nil {
				return ctrl.Result{}, utilerrors.NewAggregate([]error{err, returnedError})
			}
			logger.V(1).Info("Not found. Ignoring.")
		}
	}

	return result, returnedError
}

func (r *CertificateRequestReconciler) reconcileStatusPatch(
	logger logr.Logger,
	ctx context.Context,
	req ctrl.Request,
) (result ctrl.Result, crStatusPatch *cmapi.CertificateRequestStatus, returnedError error) {
	var cr cmapi.CertificateRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &cr); err != nil && apierrors.IsNotFound(err) {
		logger.V(1).Info("Not found. Ignoring.")
		return result, nil, nil // done
	} else if err != nil {
		return result, nil, fmt.Errorf("unexpected get error: %v", err) // retry
	}

	// Ignore CertificateRequest if it has not yet been assigned an approval
	// status condition by an approval controller.
	if !cmutil.CertificateRequestIsApproved(&cr) && !cmutil.CertificateRequestIsDenied(&cr) {
		logger.V(1).Info("CertificateRequest has not been approved or denied. Ignoring.")
		return result, nil, nil // done
	}

	// Select first matching issuer type and construct an issuerObject and issuerName
	issuerObject, issuerName := r.matchIssuerType(&cr)
	// Ignore CertificateRequest if issuerRef doesn't match one of our issuer Types
	if issuerObject == nil {
		logger.V(1).Info("Foreign issuer. Ignoring.", "group", cr.Spec.IssuerRef.Group, "kind", cr.Spec.IssuerRef.Kind)
		return result, nil, nil // done
	}
	issuerGvk := issuerObject.GetObjectKind().GroupVersionKind()

	// Ignore CertificateRequest if it is already Ready
	if cmutil.CertificateRequestHasCondition(&cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		logger.V(1).Info("CertificateRequest is Ready. Ignoring.")
		return result, nil, nil // done
	}

	// Ignore CertificateRequest if it is already Failed
	if cmutil.CertificateRequestHasCondition(&cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		logger.V(1).Info("CertificateRequest is Failed. Ignoring.")
		return result, nil, nil // done
	}

	// Ignore CertificateRequest if it is already Denied
	if cmutil.CertificateRequestHasCondition(&cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}) {
		logger.V(1).Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return result, nil, nil // done
	}

	if r.IgnoreCertificateRequest != nil {
		ignore, err := r.IgnoreCertificateRequest(ctx, signer.CertificateRequestObjectFromCertificateRequest(&cr), issuerGvk, issuerName)
		if err != nil {
			return result, nil, fmt.Errorf("failed to check if CertificateRequest should be ignored: %v", err) // retry
		}
		if ignore {
			logger.V(1).Info("Ignoring CertificateRequest")
			return result, nil, nil // done
		}
	}

	// We now have a CertificateRequest that belongs to us so we are responsible
	// for updating its Status.
	crStatusPatch = &cmapi.CertificateRequestStatus{}

	// Add a Ready condition if one does not already exist. Set initial Status
	// to Unknown.
	if ready := cmutil.GetCertificateRequestCondition(&cr, cmapi.CertificateRequestConditionReady); ready == nil {
		logger.V(1).Info("Initializing Ready condition")
		conditions.SetCertificateRequestStatusCondition(
			r.Clock,
			cr.Status.Conditions,
			&crStatusPatch.Conditions,
			cmapi.CertificateRequestConditionReady,
			cmmeta.ConditionUnknown,
			v1alpha1.CertificateRequestConditionReasonInitializing,
			fmt.Sprintf("%s has started reconciling this CertificateRequest", r.FieldOwner),
		)
		// To continue reconciling this CertificateRequest, we must re-run the reconcile loop
		// after adding the Unknown Ready condition. This update will trigger a
		// new reconcile loop, so we don't need to requeue here.
		return result, crStatusPatch, nil // apply patch, done
	}

	if cmutil.CertificateRequestIsDenied(&cr) {
		logger.V(1).Info("CertificateRequest has been denied. Marking as failed.")
		_, failedAt := conditions.SetCertificateRequestStatusCondition(
			r.Clock,
			cr.Status.Conditions,
			&crStatusPatch.Conditions,
			cmapi.CertificateRequestConditionReady,
			cmmeta.ConditionFalse,
			cmapi.CertificateRequestReasonDenied,
			"The CertificateRequest was denied by an approval controller",
		)
		crStatusPatch.FailureTime = failedAt.DeepCopy()
		r.EventRecorder.Eventf(&cr, corev1.EventTypeNormal, "DetectedDenied", "Detected that the CR is denied, will update Ready condition")
		return result, crStatusPatch, nil // done, apply patch
	}

	if err := r.Client.Get(ctx, issuerName, issuerObject); err != nil && apierrors.IsNotFound(err) {
		logger.V(1).Info("Issuer not found. Waiting for it to be created")
		conditions.SetCertificateRequestStatusCondition(
			r.Clock,
			cr.Status.Conditions,
			&crStatusPatch.Conditions,
			cmapi.CertificateRequestConditionReady,
			cmmeta.ConditionFalse,
			cmapi.CertificateRequestReasonPending,
			fmt.Sprintf("%s. Waiting for it to be created.", err),
		)
		r.EventRecorder.Eventf(&cr, corev1.EventTypeNormal, "WaitingForIssuerExist", "Waiting for the issuer to exist")
		return result, crStatusPatch, nil // done, apply patch
	} else if err != nil {
		r.EventRecorder.Eventf(&cr, corev1.EventTypeWarning, "UnexpectedError", "Got an unexpected error while processing the CR")
		return result, nil, fmt.Errorf("unexpected get error: %v", err) // retry
	}

	readyCondition := conditions.GetIssuerStatusCondition(
		issuerObject.GetStatus().Conditions,
		cmapi.IssuerConditionReady,
	)
	if (readyCondition == nil) ||
		(readyCondition.Status != cmmeta.ConditionTrue) ||
		(readyCondition.ObservedGeneration < issuerObject.GetGeneration()) {

		message := ""
		if readyCondition == nil {
			message = "Issuer is not Ready yet. No ready condition found. Waiting for it to become ready."
		} else if readyCondition.Status != cmmeta.ConditionTrue {
			message = fmt.Sprintf("Issuer is not Ready yet. Current ready condition is \"%s\": %s. Waiting for it to become ready.", readyCondition.Reason, readyCondition.Message)
		} else {
			message = "Issuer is not Ready yet. Current ready condition is outdated. Waiting for it to become ready."
		}

		logger.V(1).Info("Issuer is not Ready yet. Waiting for it to become ready.", "issuer ready condition", readyCondition)
		conditions.SetCertificateRequestStatusCondition(
			r.Clock,
			cr.Status.Conditions,
			&crStatusPatch.Conditions,
			cmapi.CertificateRequestConditionReady,
			cmmeta.ConditionFalse,
			cmapi.CertificateRequestReasonPending,
			message,
		)
		r.EventRecorder.Eventf(&cr, corev1.EventTypeNormal, "WaitingForIssuerReady", "Waiting for the issuer to become ready")
		return result, crStatusPatch, nil // done, apply patch
	}

	signedCertificate, err := r.Sign(log.IntoContext(ctx, logger), signer.CertificateRequestObjectFromCertificateRequest(&cr), issuerObject)
	if err != nil {
		// An error in the issuer part of the operator should trigger a reconcile
		// of the issuer's state.
		if issuerError := new(signer.IssuerError); errors.As(err, issuerError) {
			if reportError := r.EventSource.ReportError(
				issuerGvk, client.ObjectKeyFromObject(issuerObject),
				issuerError.Err,
			); reportError != nil {
				err = utilerrors.NewAggregate([]error{err, reportError})
			}

			logger.V(1).Error(err, "Temporary CertificateRequest error.")
			conditions.SetCertificateRequestStatusCondition(
				r.Clock,
				cr.Status.Conditions,
				&crStatusPatch.Conditions,
				cmapi.CertificateRequestConditionReady,
				cmmeta.ConditionFalse,
				cmapi.CertificateRequestReasonPending,
				"Issuer is not Ready yet. Current ready condition is outdated. Waiting for it to become ready.",
			)
			r.EventRecorder.Eventf(&cr, corev1.EventTypeWarning, "WaitingForIssuerReady", "Waiting for the issuer to become ready")
			return result, crStatusPatch, nil // done, apply patch
		}

		didCustomConditionTransition := false

		if targetCustom := new(signer.SetCertificateRequestConditionError); errors.As(err, targetCustom) {
			logger.V(1).Info("Set CertificateRequestCondition error. Setting condition.", "error", err)
			conditions.SetCertificateRequestStatusCondition(
				r.Clock,
				cr.Status.Conditions,
				&crStatusPatch.Conditions,
				targetCustom.ConditionType,
				targetCustom.Status,
				targetCustom.Reason,
				targetCustom.Error(),
			)

			// check if the custom condition transitioned
			currentCustom := cmutil.GetCertificateRequestCondition(&cr, targetCustom.ConditionType)
			didCustomConditionTransition = currentCustom == nil || currentCustom.Status != targetCustom.Status
		}

		// Check if we have still time to requeue & retry
		isPendingError := errors.As(err, &signer.PendingError{})
		isPermanentError := errors.As(err, &signer.PermanentError{})
		pastMaxRetryDuration := r.Clock.Now().After(cr.CreationTimestamp.Add(r.MaxRetryDuration))
		if !isPendingError && (isPermanentError || pastMaxRetryDuration) {
			// fail permanently
			logger.V(1).Error(err, "Permanent CertificateRequest error. Marking as failed.")
			_, failedAt := conditions.SetCertificateRequestStatusCondition(
				r.Clock,
				cr.Status.Conditions,
				&crStatusPatch.Conditions,
				cmapi.CertificateRequestConditionReady,
				cmmeta.ConditionFalse,
				cmapi.CertificateRequestReasonFailed,
				fmt.Sprintf("CertificateRequest has failed permanently: %s", err),
			)
			crStatusPatch.FailureTime = failedAt.DeepCopy()
			r.EventRecorder.Eventf(&cr, corev1.EventTypeWarning, "PermanentError", "Failed permanently to sign CertificateRequest: %s", err)
			return result, crStatusPatch, nil // done, apply patch
		} else {
			// retry
			logger.V(1).Error(err, "Retryable CertificateRequest error.")
			conditions.SetCertificateRequestStatusCondition(
				r.Clock,
				cr.Status.Conditions,
				&crStatusPatch.Conditions,
				cmapi.CertificateRequestConditionReady,
				cmmeta.ConditionFalse,
				cmapi.CertificateRequestReasonPending,
				fmt.Sprintf("CertificateRequest is not ready yet: %s", err),
			)

			r.EventRecorder.Eventf(&cr, corev1.EventTypeWarning, "RetryableError", "Failed to sign CertificateRequest, will retry: %s", err)
			if didCustomConditionTransition {
				// the reconciliation loop will be retriggered because of the added/ changed custom condition
				return result, crStatusPatch, nil // done, apply patch
			} else {
				// We trigger a reconciliation here. Controller-runtime will use exponential backoff to requeue
				// the request. We don't return an error here because we don't want controller-runtime to log an
				// additional error message and we want the metrics to show a requeue instead of an error to be
				// consistent with the other cases (see didCustomConditionTransition and Permanent error above).
				//
				// Important: This means that the ReconcileErrors metric will only be incremented in case of a
				// apiserver failure (see "unexpected get error" above). The ReconcileTotal labelRequeue metric
				// can be used instead to get some estimate of the number of requeues.
				result.Requeue = true
				return result, crStatusPatch, nil // requeue with backoff, apply patch
			}
		}
	}

	crStatusPatch.Certificate = signedCertificate.ChainPEM
	if r.SetCAOnCertificateRequest {
		crStatusPatch.CA = signedCertificate.CAPEM
	}
	conditions.SetCertificateRequestStatusCondition(
		r.Clock,
		cr.Status.Conditions,
		&crStatusPatch.Conditions,
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionTrue,
		cmapi.CertificateRequestReasonIssued,
		"issued",
	)

	logger.V(1).Info("Successfully finished the reconciliation.")
	r.EventRecorder.Eventf(&cr, corev1.EventTypeNormal, "Issued", "Succeeded signing the CertificateRequest")
	return result, crStatusPatch, nil // done, apply patch
}

func (r *CertificateRequestReconciler) setIssuersGroupVersionKind(scheme *runtime.Scheme) error {
	for _, issuerType := range r.allIssuerTypes() {
		if err := kubeutil.SetGroupVersionKind(scheme, issuerType); err != nil {
			return err
		}
	}
	return nil
}

func (r *CertificateRequestReconciler) matchIssuerType(cr *cmapi.CertificateRequest) (v1alpha1.Issuer, types.NamespacedName) {
	// Search for matching issuer
	for i, issuerType := range r.allIssuerTypes() {
		// The namespaced issuers are located in the first part of the array.
		isNamespaced := i < len(r.IssuerTypes)

		gvk := issuerType.GetObjectKind().GroupVersionKind()

		if (cr.Spec.IssuerRef.Group != gvk.Group) ||
			(cr.Spec.IssuerRef.Kind != "" && cr.Spec.IssuerRef.Kind != gvk.Kind) {
			continue
		}

		namespace := ""
		if isNamespaced {
			namespace = cr.Namespace
		}

		issuerObject := issuerType.DeepCopyObject().(v1alpha1.Issuer)
		issuerName := types.NamespacedName{
			Name:      cr.Spec.IssuerRef.Name,
			Namespace: namespace,
		}
		return issuerObject, issuerName
	}

	return nil, types.NamespacedName{}
}

func (r *CertificateRequestReconciler) allIssuerTypes() []v1alpha1.Issuer {
	issuers := make([]v1alpha1.Issuer, 0, len(r.IssuerTypes)+len(r.ClusterIssuerTypes))
	issuers = append(issuers, r.IssuerTypes...)
	issuers = append(issuers, r.ClusterIssuerTypes...)
	return issuers
}

// SetupWithManager sets up the controller with the Manager.
//
// It ensures that the Manager scheme has all the types that are needed by this controller.
// It sets up indexing of CertificateRequests by issuerRef to allow fast lookups
// of all the CertificateRequest resources associated with a particular Issuer /
// ClusterIssuer.
// It configures the controller re-reconcile all the related CertificateRequests
// when an Issuer / ClusterIssuer is created or when it changes. This ensures
// that a CertificateRequest will be properly reconciled regardless of whether
// the Issuer it references is created before or afterwards.
func (r *CertificateRequestReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := setupCertificateRequestReconcilerScheme(mgr.GetScheme()); err != nil {
		return err
	}

	crType := &cmapi.CertificateRequest{}
	if err := kubeutil.SetGroupVersionKind(mgr.GetScheme(), crType); err != nil {
		return err
	}

	if err := r.setIssuersGroupVersionKind(mgr.GetScheme()); err != nil {
		return err
	}

	build := ctrl.
		NewControllerManagedBy(mgr).
		For(
			crType,
			// We are only interested in changes to the non-ready conditions of the
			// certificaterequest, this also prevents us to get in fast reconcile loop
			// when setting the status to Pending causing the resource to update, while
			// we only want to re-reconcile with backoff/ when a resource becomes available.
			builder.WithPredicates(
				predicate.ResourceVersionChangedPredicate{},
				CertificateRequestPredicate{},
			),
		)

	// We watch all the issuer types. When an issuer receives a watch event, we
	// reconcile all the certificate requests that reference that issuer. This
	// is useful when the certificate request undergoes long backoff retry
	// periods and wouldn't react quickly to a fix in the issuer configuration.
	for _, issuerType := range r.allIssuerTypes() {
		issuerType := issuerType
		gvk := issuerType.GetObjectKind().GroupVersionKind()

		// This context is passed through to the client-go informer factory and the
		// timeout dictates how long to wait for the informer to sync with the K8S
		// API server. See:
		// * https://github.com/kubernetes-sigs/controller-runtime/issues/562
		// * https://github.com/kubernetes-sigs/controller-runtime/issues/1219
		//
		// The defaulting logic is based on:
		// https://github.com/kubernetes-sigs/controller-runtime/blob/30eae58f1b984c1b8139dd9b9f68dd2d530ed429/pkg/controller/controller.go#L138-L144
		timeout := mgr.GetControllerOptions().CacheSyncTimeout
		if timeout == 0 {
			timeout = 2 * time.Minute
		}
		cacheSyncCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		resourceHandler, err := kubeutil.NewLinkedResourceHandler(
			cacheSyncCtx,
			mgr.GetLogger(),
			mgr.GetScheme(),
			mgr.GetCache(),
			&cmapi.CertificateRequest{},
			func(rawObj client.Object) []string {
				cr := rawObj.(*cmapi.CertificateRequest)

				issuerObject, issuerName := r.matchIssuerType(cr)
				if issuerObject == nil || issuerObject.GetObjectKind().GroupVersionKind() != gvk {
					return nil
				}

				return []string{fmt.Sprintf("%s/%s", issuerName.Namespace, issuerName.Name)}
			},
			nil,
		)
		if err != nil {
			return err
		}

		build = build.Watches(
			issuerType,
			resourceHandler,
			builder.WithPredicates(
				predicate.ResourceVersionChangedPredicate{},
				LinkedIssuerPredicate{},
			),
		)
	}

	if controller, err := build.Build(r); err != nil {
		return err
	} else if r.PostSetupWithManager != nil {
		err := r.PostSetupWithManager(ctx, crType.GroupVersionKind(), mgr, controller)
		r.PostSetupWithManager = nil // free setup function
		return err
	}
	return nil
}

func setupCertificateRequestReconcilerScheme(scheme *runtime.Scheme) error {
	return cmapi.AddToScheme(scheme)
}
