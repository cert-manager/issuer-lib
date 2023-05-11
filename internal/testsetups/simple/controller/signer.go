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
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/api"
)

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;patch

// +kubebuilder:rbac:groups=testing.cert-manager.io,resources=simpleissuers;simpleclusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=testing.cert-manager.io,resources=simpleissuers/status;simpleclusterissuers/status,verbs=get;patch

type Signer struct{}

func (s Signer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return (&controllers.CombinedController{
		IssuerTypes:        []v1alpha1.Issuer{&api.SimpleIssuer{}},
		ClusterIssuerTypes: []v1alpha1.Issuer{&api.SimpleClusterIssuer{}},

		FieldOwner:       "simpleissuer.testing.cert-manager.io",
		MaxRetryDuration: 1 * time.Minute,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorderFor("simpleissuer.testing.cert-manager.io"),
	}).SetupWithManager(ctx, mgr)
}

func (Signer) Check(ctx context.Context, issuerObject client.Object) error {
	return nil
}

func (Signer) Sign(ctx context.Context, cr *cmapi.CertificateRequest, issuerObject client.Object) ([]byte, error) {
	// generate random ca private key
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
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

	// load client certificate request
	pemBlock, _ := pem.Decode(cr.Spec.Request)
	if pemBlock == nil {
		return nil, fmt.Errorf("pem.Decode failed")
	}
	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if err = clientCSR.CheckSignature(); err != nil {
		return nil, err
	}

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		panic(err)
	}

	clientCrt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	return clientCrt, nil
}
