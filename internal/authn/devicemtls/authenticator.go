package devicemtls

import (
	"context"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	runtime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

// Authenticator is the M4.5 DeviceMTLS authenticator. The trusted-proxy
// source has already verified the proxy hop and resolved the certificate
// server-side; this authenticator converts the resolved device credential into
// the typed DeviceMTLS binding and fails closed on any empty identity field.
//
// Proxy trust is a prerequisite for DeviceMTLS, not an application credential
// kind: this authenticator serves only CredentialKindDeviceMTLS.
type Authenticator struct{}

// NewAuthenticator constructs the DeviceMTLS authenticator.
func NewAuthenticator() *Authenticator { return &Authenticator{} }

// Kind returns DeviceMTLS.
func (Authenticator) Kind() authpolicy.CredentialKind {
	return authpolicy.CredentialKindDeviceMTLS
}

// Authenticate converts a resolved device credential into a typed binding.
func (Authenticator) Authenticate(_ context.Context, c *runtime.Credential) runtime.AuthenticationResult {
	if c == nil || c.Device == nil {
		return runtime.AuthenticationResult{Decision: runtime.DecisionRejected}
	}
	b, err := runtime.NewDeviceMTLSBinding(c.Device.DeviceID, c.Device.CertificateID, c.Device.IssuedForEnrollmentID)
	if err != nil {
		// The source produced an incomplete resolved identity: trusted
		// verification material failure, never a client credential rejection.
		return runtime.AuthenticationResult{Decision: runtime.DecisionIndeterminate}
	}
	return runtime.AuthenticationResult{Decision: runtime.DecisionAuthenticated, Binding: b}
}
