 # cert-manager intree

## Motivation

As we migrate in-tree issuers out of `cert-manager` repo, there is a need to avoid repeating the logic of watching for
`cert-manager` `Issuers` and `ClusterIssuers`. This is because as we migrate intree issuers we want to maintain backwards compatiblity, which means we need to maintain the same `Issuer`/`ClusterIssuer` configuration. This package aims to address that requirement. It consumes the `WrapperIssuer` interface defined in `api/<Version>/issuer_interface.go`.

Currently, the intree package allows the caller to watch for two **`cert-manager`** resources:

* Issuer
* ClusterIssuer

## Example

```go
func (s Signer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return (&controllers.CombinedController{
		IssuerTypes:        intree.Issuers, // Monitors CM Issuer
		ClusterIssuerTypes: intree.ClusterIssuers, // Monitors CM ClusterIssuer

		FieldOwner:       "simpleissuer.testing.cert-manager.io",
		MaxRetryDuration: 1 * time.Minute,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorderFor("simpleissuer.testing.cert-manager.io"),
	}).SetupWithManager(ctx, mgr)
}
```
