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
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
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

// CertificateSigningRequestReconciler reconciles a CertificateRequest object
type CertificateSigningRequestReconciler struct {
	IssuerTypes        []v1alpha1.Issuer
	ClusterIssuerTypes []v1alpha1.Issuer

	FieldOwner       string
	MaxRetryDuration time.Duration
	EventSource      kubeutil.EventSource

	// Client is a controller-runtime client used to get and set K8S API resources
	client.Client
	// Sign connects to a CA and returns a signed certificate for the supplied CertificateRequest.
	signer.Sign

	// EventRecorder is used for creating Kubernetes events on resources.
	EventRecorder record.EventRecorder

	// Clock is used to mock condition transition times in tests.
	Clock clock.PassiveClock

	PostSetupWithManager func(context.Context, schema.GroupVersionKind, ctrl.Manager, controller.Controller) error
}

func (r *CertificateSigningRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, returnedError error) {
	logger := log.FromContext(ctx).WithName("Reconcile")

	logger.V(2).Info("Starting reconcile loop", "name", req.Name, "namespace", req.Namespace)

	result, csrStatusPatch, returnedError := r.reconcileStatusPatch(logger, ctx, req)
	logger.V(2).Info("Got StatusPatch result", "result", result, "patch", csrStatusPatch, "error", returnedError)
	if csrStatusPatch != nil {
		cr, patch, err := ssaclient.GenerateCertificateSigningRequestStatusPatch(req.Name, req.Namespace, csrStatusPatch)
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

func (r *CertificateSigningRequestReconciler) reconcileStatusPatch(
	logger logr.Logger,
	ctx context.Context,
	req ctrl.Request,
) (result ctrl.Result, csrStatusPatch *certificatesv1.CertificateSigningRequestStatus, returnedError error) {
	var csr certificatesv1.CertificateSigningRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &csr); err != nil && apierrors.IsNotFound(err) {
		logger.V(1).Info("Not found. Ignoring.")
		return result, nil, nil // done
	} else if err != nil {
		return result, nil, fmt.Errorf("unexpected get error: %v", err) // retry
	}

	// Ignore CertificateRequest if it has not yet been assigned an approval
	// status condition by an approval controller.
	if !util.CertificateSigningRequestIsApproved(&csr) && !util.CertificateSigningRequestIsDenied(&csr) {
		logger.V(1).Info("CertificateSigningRequest has not been approved or denied. Ignoring.")
		return result, nil, nil // done
	}

	// Select first matching issuer type and construct an issuerObject and issuerName
	issuerObject, issuerName, err := r.matchIssuerType(&csr)
	// Ignore CertificateRequest if issuerRef doesn't match one of our issuer Types
	if err != nil {
		logger.V(1).Info("Foreign issuer. Ignoring.", "error", err)
		return result, nil, nil // done
	}
	issuerGvk := issuerObject.GetObjectKind().GroupVersionKind()

	// Ignore CertificateRequest if it is already Ready
	if len(csr.Status.Certificate) > 0 {
		logger.V(1).Info("CertificateSigningRequest is Ready. Ignoring.")
		return result, nil, nil // done
	}

	// Ignore CertificateRequest if it is already Failed
	if util.CertificateSigningRequestIsFailed(&csr) {
		logger.V(1).Info("CertificateSigningRequest is Failed. Ignoring.")
		return result, nil, nil // done
	}

	// Ignore CertificateRequest if it is Denied
	if util.CertificateSigningRequestIsDenied(&csr) {
		logger.V(1).Info("CertificateSigningRequest is Denied. Ignoring.")
		return result, nil, nil // done
	}

	// We now have a CertificateSigningRequestStatus that belongs to us so we are responsible
	// for updating its Status.
	csrStatusPatch = &certificatesv1.CertificateSigningRequestStatus{}

	if err := r.Client.Get(ctx, issuerName, issuerObject); err != nil && apierrors.IsNotFound(err) {
		logger.V(1).Info("Issuer not found. Waiting for it to be created")
		r.EventRecorder.Eventf(&csr, corev1.EventTypeNormal, "WaitingForIssuerExist", "Waiting for the issuer to exist")
		return result, csrStatusPatch, nil // done, apply patch
	} else if err != nil {
		r.EventRecorder.Eventf(&csr, corev1.EventTypeWarning, "UnexpectedError", "Got an unexpected error while processing the CR")
		return result, nil, fmt.Errorf("unexpected get error: %v", err) // retry
	}

	readyCondition := conditions.GetIssuerStatusCondition(
		issuerObject.GetStatus().Conditions,
		cmapi.IssuerConditionReady,
	)
	if (readyCondition == nil) ||
		(readyCondition.Status != cmmeta.ConditionTrue) ||
		(readyCondition.ObservedGeneration < issuerObject.GetGeneration()) {

		logger.V(1).Info("Issuer is not Ready yet. Waiting for it to become ready.", "issuer ready condition", readyCondition)
		r.EventRecorder.Eventf(&csr, corev1.EventTypeNormal, "WaitingForIssuerReady", "Waiting for the issuer to become ready")
		return result, csrStatusPatch, nil // done, apply patch
	}

	signedCertificate, err := r.Sign(log.IntoContext(ctx, logger), signer.CertificateRequestObjectFromCertificateSigningRequest(&csr), issuerObject)
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

			r.EventRecorder.Eventf(&csr, corev1.EventTypeWarning, "WaitingForIssuerReady", "Waiting for the issuer to become ready")
			return result, csrStatusPatch, nil // done, apply patch
		}

		didCustomConditionTransition := false

		if targetCustom := new(signer.SetCertificateRequestConditionError); errors.As(err, targetCustom) {
			logger.V(1).Info("Set CertificateRequestCondition error. Setting condition.", "error", err)
			conditions.SetCertificateSigningRequestStatusCondition(
				r.Clock,
				csr.Status.Conditions,
				&csrStatusPatch.Conditions,
				certificatesv1.RequestConditionType(targetCustom.ConditionType),
				corev1.ConditionStatus(targetCustom.Status),
				targetCustom.Reason,
				targetCustom.Error(),
			)

			// check if the custom condition transitioned
			currentCustom := conditions.GetCertificateSigningRequestStatusCondition(csr.Status.Conditions, certificatesv1.RequestConditionType(targetCustom.ConditionType))
			didCustomConditionTransition = currentCustom == nil || currentCustom.Status != corev1.ConditionStatus(targetCustom.Status)
		}

		// Check if we have still time to requeue & retry
		isPendingError := errors.As(err, &signer.PendingError{})
		isPermanentError := errors.As(err, &signer.PermanentError{})
		pastMaxRetryDuration := r.Clock.Now().After(csr.CreationTimestamp.Add(r.MaxRetryDuration))
		if !isPendingError && (isPermanentError || pastMaxRetryDuration) {
			// fail permanently
			logger.V(1).Error(err, "Permanent CertificateRequest error. Marking as failed.")

			conditions.SetCertificateSigningRequestStatusCondition(
				r.Clock,
				csr.Status.Conditions,
				&csrStatusPatch.Conditions,
				certificatesv1.CertificateFailed,
				corev1.ConditionTrue,
				cmapi.CertificateRequestReasonFailed,
				fmt.Sprintf("CertificateRequest has failed permanently: %s", err),
			)
			r.EventRecorder.Eventf(&csr, corev1.EventTypeWarning, "PermanentError", "Failed permanently to sign CertificateRequest: %s", err)
			return result, csrStatusPatch, nil // done, apply patch
		} else {
			// retry
			logger.V(1).Error(err, "Retryable CertificateRequest error.")

			r.EventRecorder.Eventf(&csr, corev1.EventTypeWarning, "RetryableError", "Failed to sign CertificateRequest, will retry: %s", err)
			if didCustomConditionTransition {
				// the reconciliation loop will be retriggered because of the added/ changed custom condition
				return result, csrStatusPatch, nil // done, apply patch
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
				return result, csrStatusPatch, nil // requeue with backoff, apply patch
			}
		}
	}

	csrStatusPatch.Certificate = signedCertificate

	logger.V(1).Info("Successfully finished the reconciliation.")
	r.EventRecorder.Eventf(&csr, corev1.EventTypeNormal, "Issued", "Succeeded signing the CertificateRequest")
	return result, csrStatusPatch, nil // done, apply patch
}

func (r *CertificateSigningRequestReconciler) setIssuersGroupVersionKind(scheme *runtime.Scheme) error {
	for _, issuerType := range r.allIssuerTypes() {
		if err := kubeutil.SetGroupVersionKind(scheme, issuerType); err != nil {
			return err
		}
	}
	return nil
}

// matchIssuerType returns the IssuerType and IssuerName that matches the
// signerName of the CertificateSigningRequest. If no match is found, an error
// is returned.
// The signerName of the CertificateSigningRequest should be in the format
// "<issuer-type-id>/<issuer-id>". The issuer-type-id is obtained from the
// GetIssuerTypeIdentifier function of the IssuerType.
// The issuer-id is "<name>" for a ClusterIssuer resource.
func (r *CertificateSigningRequestReconciler) matchIssuerType(csr *certificatesv1.CertificateSigningRequest) (v1alpha1.Issuer, types.NamespacedName, error) {
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
	for i, issuerType := range r.allIssuerTypes() {
		// The namespaced issuers are located in the first part of the array.
		isNamespaced := i < len(r.IssuerTypes)

		if issuerTypeIdentifier != issuerType.GetIssuerTypeIdentifier() {
			continue
		}

		issuerObject := issuerType.DeepCopyObject().(v1alpha1.Issuer)

		issuerName := types.NamespacedName{
			Name: issuerIdentifier,
		}

		if isNamespaced {
			return nil, types.NamespacedName{}, fmt.Errorf("invalid SignerName, %q is a namespaced issuer type, namespaced issuers are not supported for Kubernetes CSRs", issuerTypeIdentifier)
		}

		return issuerObject, issuerName, nil
	}

	return nil, types.NamespacedName{}, fmt.Errorf("no issuer found for signer name: %q", csr.Spec.SignerName)
}

func (r *CertificateSigningRequestReconciler) allIssuerTypes() []v1alpha1.Issuer {
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
func (r *CertificateSigningRequestReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := setupCertificateSigningRequestReconcilerScheme(mgr.GetScheme()); err != nil {
		return err
	}

	crType := &certificatesv1.CertificateSigningRequest{}
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
				CertificateSigningRequestPredicate{},
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
			&certificatesv1.CertificateSigningRequest{},
			func(rawObj client.Object) []string {
				csr := rawObj.(*certificatesv1.CertificateSigningRequest)

				issuerObject, issuerName, err := r.matchIssuerType(csr)
				if err != nil || issuerObject.GetObjectKind().GroupVersionKind() != gvk {
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

func setupCertificateSigningRequestReconcilerScheme(scheme *runtime.Scheme) error {
	return certificatesv1.AddToScheme(scheme)
}
