package rbac

import (
	"k8s.io/client-go/rest"
)

// Suite defines a reusable conformance test suite that can be used against any
// Issuer implementation.
type Suite struct {
	// KubeClientConfig is the configuration used to connect to the Kubernetes
	// API server.
	KubeClientConfig *rest.Config
}

func (s *Suite) Define() {
	s.defineCertificates()
	s.defineCertificateRequests()
	s.defineIssuers()
}
