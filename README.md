<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>
<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/issuer-lib"><img src="https://godoc.org/github.com/cert-manager/issuer-lib?status.svg" alt="cert-manager/issuer-lib godoc"></a>
  <a href="https://goreportcard.com/report/github.com/cert-manager/issuer-lib"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/issuer-lib" /></a>
</p>

# cert-manager issuer-lib

> issuer-lib is the Go library for building cert-manager issuers.

See `./internal/testsetups/simple` for an example of creating an issuer based on this library.

---

⚠️ Warning: This library is ready to be used in production, but the API is still subject to change.
Developers using this library might have to update their code when updating to a newer version.

---

## How it works

This repository provides a go libary that you can use for creating cert-manager controllers for your own Issuers.

To use the libary, your Issuer API types have to implement the `v1alpha1.Issuer` interface.
The business logic of the controllers can be provided to the libary through the `Check` and `Sign` functions.
- The `Check` function is used by the Issuer controllers.  
If it returns a normal error, the controller will retry with backoff until the `Check` function succeeds.  
If the error is of type `signer.PermanentError`, the controller will not retry automatically. Instead, an increase in Generation is required to recheck the issuer.

- The `Sign` function is used by the CertificateRequest controller.
If it returns a normal error, the `Sign` function will be retried as long as we have not spent more than the configured `MaxRetryDuration` after the certificate request was created.  
If the error is of type `signer.IssuerError`, the error is an error that should be set on the issuer instead of the CertificateRequest.  
If the error is of type `signer.SetCertificateRequestConditionError`, the controller will, additional to setting the ready condition, also set the specified condition. This can be used in case we have to store some additional state in the status.  
If the error is of type `signer.PermanentError`, the controller will not retry automatically. Instead, a new CertificateRequest has to be created.

## Reconciliation loops

The reconciliation function of the CertificateRequest controller will:
1. wait for the request to be Approved/ Denied
2. only consider the configured Issuer API types
3. leave Ready/ Failed/ Denied CertificateRequests as-is
4. start by setting the Ready condition to Initializing
5. set the Ready condition to Denied if the CertificateRequest is denied
6. wait for the linked Issuer to exist and be in an up-to-date Ready state
7. call the `Sign` function and handle errors as described above
8. update the CertificateRequest with the returned Signed Certificate and set the state to Ready

The reconciliation function of the Issuer controllers will:
1. only reconcile if the Ready condition is not "failed permanently" or the CertificateRequest controller notified that the Ready condition is no longer valid
2. if the issuer status is Ready and we received an issuer error from the CertificateRequest controller, set the Ready condition to false and set the error
3. start by setting the Ready condition to Initializing
4. call the `Check` function and handle errors as described above
5. update the Issuer by setting the state to Ready

Note that a reconciliation will only be triggered:
- for CertificateRequests:
    - on create
    - on update when an annotation is changed/ added or removed
    - on update when a condition is added or removed
    - on update when a non-readiness condition is changed
    - on update when the Ready condition of the linked Issuer is changed/ added or removed
    - when triggered in the previous reconciliation

- for Issuers:
    - on create
    - on update when an annotation is changed/ added or removed
    - on update when the generation (.Spec) changes
    - on update when the Ready condition was added/ removed
    - when triggered in the previous reconciliation
