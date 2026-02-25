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

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	simplev1alpha1 "simple-issuer/api/v1alpha1"
)

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign,resourceNames=simpleissuers.testing.cert-manager.io/*;simpleclusterissuers.testing.cert-manager.io/*

// +kubebuilder:rbac:groups=testing.cert-manager.io,resources=simpleissuers;simpleclusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=testing.cert-manager.io,resources=simpleissuers/status;simpleclusterissuers/status,verbs=patch

// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

type asyncSigner struct {
	startupTime time.Time
	asyncIssuer *asyncIssuer
}

func NewSigner() *asyncSigner {
	return &asyncSigner{
		startupTime: time.Now(),
		asyncIssuer: &asyncIssuer{
			signGoroutines: make(map[int]chan signResult),
		},
	}
}

func (s *asyncSigner) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return (&controllers.CombinedController{
		IssuerTypes:        []v1alpha1.Issuer{&simplev1alpha1.SimpleIssuer{}},
		ClusterIssuerTypes: []v1alpha1.Issuer{&simplev1alpha1.SimpleClusterIssuer{}},

		FieldOwner:       "simpleissuer.testing.cert-manager.io",
		MaxRetryDuration: 1 * time.Minute,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorder("simpleissuer.testing.cert-manager.io"),
	}).SetupWithManager(ctx, mgr)
}

var atomicAvailabilityCounter atomic.Int32

func (s *asyncSigner) isAvailable() error {
	// Fake a signer that is unavailable for the first 3 seconds after successfully starting up, and
	// which becomes available after that. This can be used to test the behavior of the controller when
	// the Sign function returns an IssuerError.
	if time.Since(s.startupTime) < 3*time.Second && atomicAvailabilityCounter.Add(1) > 0 {
		return fmt.Errorf("signer is unavailable during startup")
	}

	return nil
}

func (s *asyncSigner) Check(ctx context.Context, issuerObject v1alpha1.Issuer) error {
	return s.isAvailable()
}

const signingInProgressConditionType = "SigningInProgress"

func (s *asyncSigner) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject v1alpha1.Issuer) signer.SignResult {
	if err := s.isAvailable(); err != nil {
		return signer.SignError(signer.IssuerError{Err: err})
	}

	customCondition := func() *metav1.Condition {
		for _, cond := range cr.GetConditions() {
			if cond.Type == signingInProgressConditionType {
				return &cond
			}
		}
		return nil
	}()

	var pickupGoroutineID int
	if customCondition != nil {
		goroutineID, err := strconv.Atoi(strings.TrimPrefix(customCondition.Reason, "Goroutine"))
		if err != nil {
			// This will clear the custom condition.
			return signer.SignError(fmt.Errorf("invalid goroutine ID in custom condition: %v", err))
		}

		completed, cert, err := s.asyncIssuer.check(goroutineID)
		if err != nil {
			// Signing failed, remove the custom condition and return the error, will retry.
			return signer.SignError(fmt.Errorf("signing failed: %v", err))
		}
		if completed {
			// Signing is complete, remove the custom condition and return success.
			return signer.SignSuccess(cert)
		}

		// Signing is still in progress
		pickupGoroutineID = goroutineID
	} else {
		details, err := cr.GetCertificateDetails()
		if err != nil {
			return signer.SignError(fmt.Errorf("failed to get certificate details: %v", err))
		}

		template, err := details.CertificateTemplate()
		if err != nil {
			return signer.SignError(fmt.Errorf("failed to create certificate template: %v", err))
		}

		pickupGoroutineID = s.asyncIssuer.startSigning(template)
	}

	return signer.SignError(signer.PendingError{
		Err:          fmt.Errorf("signing is still in progress, retrying after some time"),
		RequeueAfter: 1 * time.Second,
	}, signer.WithCustomConditions(metav1.Condition{
		Type:    signingInProgressConditionType,
		Status:  metav1.ConditionTrue,
		Reason:  fmt.Sprintf("Goroutine%d", pickupGoroutineID),
		Message: "Signing is still in progress",
	}))
}

type asyncIssuer struct {
	mu             sync.Mutex
	counter        int
	signGoroutines map[int]chan signResult
}

type signResult struct {
	result []byte
	err    error
}

// check checks if the signing goroutine with the given ID has completed, and returns the result if it has.
// otherswise, it returns (false, nil, nil) to indicate the signing is still in progress.
func (s *asyncIssuer) check(goroutineID int) (bool, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	done, exists := s.signGoroutines[goroutineID]
	if !exists {
		return true, nil, fmt.Errorf("no signing goroutine found for ID %d", goroutineID)
	}

	select {
	case signResult := <-done:
		delete(s.signGoroutines, goroutineID)
		if signResult.err != nil {
			return true, nil, fmt.Errorf("signing failed: %v", signResult.err)
		}
		return true, signResult.result, nil
	default:
		return false, nil, nil
	}
}

// startSigning starts a new goroutine to perform the signing operation asynchronously, and returns the ID of the goroutine.
// The signing result can be retrieved later using the check method with the returned goroutine ID.
func (s *asyncIssuer) startSigning(template *x509.Certificate) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.counter += 1
	goroutineID := s.counter
	done := make(chan signResult)
	s.signGoroutines[goroutineID] = done

	go func() {
		// Simulate some work being done in the goroutine.
		time.Sleep(5 * time.Second)

		caPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			done <- signResult{nil, fmt.Errorf("failed to generate CA private key: %v", err)}
			return
		}

		caCRT := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Acme Co"},
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour * 24 * 180),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		clientCRTRaw, err := x509.CreateCertificate(rand.Reader, template, caCRT, template.PublicKey, caPrivateKey)
		if err != nil {
			done <- signResult{nil, fmt.Errorf("failed to create client certificate: %v", err)}
			return
		}

		clientCrt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
		done <- signResult{clientCrt, nil}
	}()

	return goroutineID
}
