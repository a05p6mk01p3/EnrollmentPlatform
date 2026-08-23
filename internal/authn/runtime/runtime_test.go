package runtime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// --- helpers ---

func loadYAMLSpec(t *testing.T, yaml string) *openapi3.T {
	t.Helper()
	spec, err := openapi3.NewLoader().LoadFromData([]byte(yaml))
	if err != nil {
		t.Fatalf("load YAML spec: %v", err)
	}
	return spec
}

// compileSynthetic compiles a synthetic spec and returns the policy for the
// single operation it contains.
func compileSynthetic(t *testing.T, yaml string) (*openapi3.T, *authpolicy.Policy, *authpolicy.OperationPolicy) {
	t.Helper()
	spec := loadYAMLSpec(t, yaml)
	p, err := authpolicy.Compile(spec)
	if err != nil {
		t.Fatalf("Compile synthetic: %v", err)
	}
	var op *authpolicy.OperationPolicy
	for _, o := range p.Operations() {
		if op != nil {
			t.Fatalf("synthetic spec has more than one operation")
		}
		op = o
	}
	if op == nil {
		t.Fatal("synthetic spec has no operation")
	}
	return spec, p, op
}

func acceptBearer(kind authpolicy.CredentialKind, token string) Authenticator {
	return BearerTestAuthenticator{KindValue: kind, Decide: func(t string) Decision {
		if t == token {
			return DecisionAuthenticated
		}
		return DecisionRejected
	}}
}

func acceptAllBearer(kind authpolicy.CredentialKind) Authenticator {
	return BearerTestAuthenticator{KindValue: kind, Decide: func(t string) Decision {
		if t == "" {
			return DecisionRejected
		}
		return DecisionAuthenticated
	}}
}

func rejectAllBearer(kind authpolicy.CredentialKind) Authenticator {
	return BearerTestAuthenticator{KindValue: kind, Decide: func(string) Decision { return DecisionRejected }}
}

func indeterminateBearer(kind authpolicy.CredentialKind) Authenticator {
	return BearerTestAuthenticator{KindValue: kind, Decide: func(string) Decision { return DecisionIndeterminate }}
}

func acceptDevice() Authenticator {
	return DeviceTestAuthenticator{Decide: func(d *DeviceCredential) Decision {
		if d == nil {
			return DecisionRejected
		}
		return DecisionAuthenticated
	}}
}

func rejectDevice() Authenticator {
	return DeviceTestAuthenticator{Decide: func(*DeviceCredential) Decision { return DecisionRejected }}
}

func presentDevice() DeviceMTLSSource {
	return DeviceTestSource{Credential: func(r *http.Request) (*DeviceCredential, error) { return &DeviceCredential{}, nil }}
}

func newRT(t *testing.T, spec *openapi3.T, policy *authpolicy.Policy, registry *Registry, source DeviceMTLSSource) *Runtime {
	t.Helper()
	rt, err := NewRuntime(spec, policy, registry, source, 262144, 4<<20)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return rt
}

func bearerRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func wantErrorKind(t *testing.T, err error, want errorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("authenticate succeeded; want failure kind %d", want)
	}
	var ae *authnError
	if !errors.As(err, &ae) {
		t.Fatalf("error %v is not an authnError", err)
	}
	if ae.kind != want {
		t.Fatalf("error kind = %d; want %d (%v)", ae.kind, want, err)
	}
}

// --- bearer extraction (§5) ---

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		name    string
		values  []string
		wantTok string
		wantOK  bool
		wantErr error
	}{
		{"absent", nil, "", false, nil},
		{"valid", []string{"Bearer abc123"}, "abc123", true, nil},
		{"lowercase scheme", []string{"bearer abc123"}, "abc123", true, nil},
		{"mixed case scheme", []string{"BeArEr abc123"}, "abc123", true, nil},
		{"leading spaces after scheme", []string{"Bearer   abc123"}, "abc123", true, nil},
		{"tab separator", []string{"Bearer\tabc123"}, "abc123", true, nil},
		{"duplicate header lines", []string{"Bearer a", "Bearer b"}, "", false, errBearerDuplicate},
		{"combined credentials", []string{"Bearer a, Bearer b"}, "", false, errBearerMalformed},
		{"comma inside token", []string{"Bearer a,b"}, "", false, errBearerMalformed},
		{"empty token", []string{"Bearer"}, "", false, errBearerEmpty},
		{"bare Bearer with trailing space", []string{"Bearer "}, "", false, errBearerEmpty},
		{"non-bearer scheme", []string{"Basic abc"}, "", false, errBearerMalformed},
		{"bare unknown scheme", []string{"Basic"}, "", false, errBearerMalformed},
		{"space inside token", []string{"Bearer abc def"}, "", false, errBearerMalformed},
		{"trailing space in value", []string{"Bearer abc "}, "", false, errBearerMalformed},
		{"leading space in value", []string{" Bearer abc"}, "", false, errBearerMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, present, err := extractBearer(tc.values)
			if present != tc.wantOK {
				t.Fatalf("present = %v; want %v (err %v)", present, tc.wantOK, err)
			}
			if tok != tc.wantTok {
				t.Fatalf("token = %q; want %q", tok, tc.wantTok)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("err = %v; want nil", err)
			}
			if tc.wantErr != nil && err != tc.wantErr {
				t.Fatalf("err = %v; want %v", err, tc.wantErr)
			}
		})
	}
}

// --- registry ---

func TestRegistryRejectsDuplicateKind(t *testing.T) {
	_, err := NewRegistry(
		rejectAllBearer(authpolicy.CredentialKindHumanOIDC),
		rejectAllBearer(authpolicy.CredentialKindHumanOIDC),
	)
	if err == nil {
		t.Fatal("duplicate kind accepted")
	}
	var dke *DuplicateKindError
	if !errors.As(err, &dke) {
		t.Fatalf("error %v is not a DuplicateKindError", err)
	}
}

// --- OR/AND runtime evaluation (§9, §26 of M4.1) ---

const orSpecYAML = `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /x:
    get:
      operationId: orOp
      responses:
        '200': {description: ok}
      security:
        - HumanOIDC: []
        - DeviceMTLS: []
components:
  securitySchemes:
    HumanOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
    DeviceMTLS: {type: mutualTLS}
`

const andSpecYAML = `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /x:
    get:
      operationId: andOp
      responses:
        '200': {description: ok}
      security:
        - HumanOIDC: []
          DeviceMTLS: []
components:
  securitySchemes:
    HumanOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
    DeviceMTLS: {type: mutualTLS}
`

func TestORRuntimeSemantics(t *testing.T) {
	spec, policy, op := compileSynthetic(t, orSpecYAML)
	registry, err := NewRegistry(acceptBearer(authpolicy.CredentialKindHumanOIDC, "tok"), acceptDevice())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("bearer alternative satisfies", func(t *testing.T) {
		rt := newRT(t, spec, policy, registry, nil)
		ac, err := rt.authenticate(bearerRequest(t, "tok"), op)
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		if !ac.Has(authpolicy.CredentialKindHumanOIDC) {
			t.Fatal("HumanOIDC not in context")
		}
	})

	t.Run("device alternative satisfies", func(t *testing.T) {
		rt := newRT(t, spec, policy, registry, presentDevice())
		ac, err := rt.authenticate(bearerRequest(t, ""), op)
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		if !ac.Has(authpolicy.CredentialKindDeviceMTLS) {
			t.Fatal("DeviceMTLS not in context")
		}
	})

	t.Run("neither alternative fails closed", func(t *testing.T) {
		rt := newRT(t, spec, policy, registry, nil)
		_, err := rt.authenticate(bearerRequest(t, "wrong"), op)
		wantErrorKind(t, err, errorKindAuthenticationRequired)
	})
}

func TestANDRuntimeSemantics(t *testing.T) {
	spec, policy, op := compileSynthetic(t, andSpecYAML)
	registry, err := NewRegistry(acceptBearer(authpolicy.CredentialKindHumanOIDC, "tok"), acceptDevice())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("full AND satisfies", func(t *testing.T) {
		rt := newRT(t, spec, policy, registry, presentDevice())
		ac, err := rt.authenticate(bearerRequest(t, "tok"), op)
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		if !ac.Has(authpolicy.CredentialKindHumanOIDC) || !ac.Has(authpolicy.CredentialKindDeviceMTLS) {
			t.Fatalf("context = %v; want both kinds", ac.Kinds())
		}
	})

	t.Run("partial AND fails closed", func(t *testing.T) {
		// Bearer accepted, device absent: only half of the conjunction.
		rt := newRT(t, spec, policy, registry, nil)
		_, err := rt.authenticate(bearerRequest(t, "tok"), op)
		wantErrorKind(t, err, errorKindAuthenticationRequired)
	})
}

// --- bearer classification (§6, §9) ---

func TestBearerClassificationAmbiguityFailsClosed(t *testing.T) {
	spec, policy, op := compileSynthetic(t, `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /x:
    get:
      operationId: twoBearerOp
      responses:
        '200': {description: ok}
      security:
        - HumanOIDC: []
        - AdminOIDC: []
components:
  securitySchemes:
    HumanOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
    AdminOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
`)
	registry, err := NewRegistry(
		acceptAllBearer(authpolicy.CredentialKindHumanOIDC),
		acceptAllBearer(authpolicy.CredentialKindAdminOIDC),
	)
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, nil)
	_, err = rt.authenticate(bearerRequest(t, "shared"), op)
	wantErrorKind(t, err, errorKindAmbiguousCredential)
}

func TestBearerClassificationExactlyOne(t *testing.T) {
	spec, policy, op := compileSynthetic(t, `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /x:
    get:
      operationId: twoBearerOp
      responses:
        '200': {description: ok}
      security:
        - HumanOIDC: []
        - AdminOIDC: []
components:
  securitySchemes:
    HumanOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
    AdminOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
`)
	registry, err := NewRegistry(
		acceptBearer(authpolicy.CredentialKindHumanOIDC, "human-tok"),
		acceptBearer(authpolicy.CredentialKindAdminOIDC, "admin-tok"),
	)
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, nil)
	ac, err := rt.authenticate(bearerRequest(t, "human-tok"), op)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !ac.Has(authpolicy.CredentialKindHumanOIDC) || ac.Has(authpolicy.CredentialKindAdminOIDC) {
		t.Fatalf("context kinds = %v; want only HumanOIDC", ac.Kinds())
	}
}

func TestIndeterminateFailsClosed(t *testing.T) {
	spec, policy, op := compileSynthetic(t, orSpecYAML)
	registry, err := NewRegistry(indeterminateBearer(authpolicy.CredentialKindHumanOIDC), acceptDevice())
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, nil)
	_, err = rt.authenticate(bearerRequest(t, "tok"), op)
	wantErrorKind(t, err, errorKindDependencyUnavailable)
}

func TestMissingAuthenticatorFailsClosed(t *testing.T) {
	spec, policy, op := compileSynthetic(t, orSpecYAML)
	registry, err := NewRegistry(acceptDevice()) // HumanOIDC authenticator missing
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, nil)
	_, err = rt.authenticate(bearerRequest(t, "tok"), op)
	wantErrorKind(t, err, errorKindDependencyUnavailable)
}

// --- simultaneous bearer + device, no universal preference (§10) ---

func TestSimultaneousBearerAndDeviceNoPreference(t *testing.T) {
	spec, policy, op := compileSynthetic(t, `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /x:
    get:
      operationId: bothOp
      responses:
        '200': {description: ok}
      security:
        - EnrollmentAccessToken: []
        - DeviceMTLS: []
components:
  securitySchemes:
    EnrollmentAccessToken: {type: http, scheme: bearer, bearerFormat: opaque}
    DeviceMTLS: {type: mutualTLS}
`)
	registry, err := NewRegistry(acceptBearer(authpolicy.CredentialKindEnrollmentAccessToken, "tok"), acceptDevice())
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, presentDevice())
	ac, err := rt.authenticate(bearerRequest(t, "tok"), op)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !ac.Has(authpolicy.CredentialKindEnrollmentAccessToken) || !ac.Has(authpolicy.CredentialKindDeviceMTLS) {
		t.Fatalf("context kinds = %v; want both", ac.Kinds())
	}
}

// --- AuthenticationContext immutability (§11) ---

func TestAuthenticationContextImmutable(t *testing.T) {
	spec, policy, op := compileSynthetic(t, orSpecYAML)
	registry, err := NewRegistry(acceptBearer(authpolicy.CredentialKindHumanOIDC, "tok"), acceptDevice())
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, presentDevice())
	ac, err := rt.authenticate(bearerRequest(t, "tok"), op)
	if err != nil {
		t.Fatal(err)
	}

	kinds := ac.Kinds()
	kinds[0] = authpolicy.CredentialKindDeviceMTLS
	if !ac.Has(authpolicy.CredentialKindHumanOIDC) {
		t.Fatal("internal kinds mutated through accessor")
	}

	sat := ac.SatisfiedAlternatives()
	sat[0] = authpolicy.Conjunction{}
	if got := ac.SatisfiedAlternatives(); len(got) == 0 || got[0].Len() == 0 {
		t.Fatal("internal satisfied alternatives mutated through accessor")
	}
}

// --- discriminator extraction + body preservation (§13) ---

const conditionalSpecYAML = `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /c:
    post:
      operationId: condOp
      requestBody:
        required: true
        content:
          application/json:
            schema:
              oneOf:
                - $ref: '#/components/schemas/KA'
                - $ref: '#/components/schemas/KB'
              discriminator:
                propertyName: kind
                mapping:
                  KA: '#/components/schemas/KA'
                  KB: '#/components/schemas/KB'
      responses:
        '200': {description: ok}
      security:
        - HumanOIDC: []
        - AdminOIDC: []
      x-security-conditions:
        discriminator: kind
        cases:
          KA:
            requiredSecurityScheme: HumanOIDC
          KB:
            requiredSecurityScheme: AdminOIDC
        enforcement: MANDATORY_SERVER_POLICY_AND_CONTRACT_TEST
components:
  securitySchemes:
    HumanOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
    AdminOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
  schemas:
    KA:
      type: object
      required: [kind, pad]
      properties:
        kind: {type: string, const: KA}
        pad: {type: string}
    KB:
      type: object
      required: [kind, pad]
      properties:
        kind: {type: string, const: KB}
        pad: {type: string}
`

func TestExtractDiscriminatorPreservesBody(t *testing.T) {
	spec, policy, _ := compileSynthetic(t, conditionalSpecYAML)
	rt := newRT(t, spec, policy, DefaultDenyRegistry(), nil)

	body := `{"pad":"some padding that comes first in the object","kind":"KB"}`
	req := httptest.NewRequest(http.MethodPost, "/c", strings.NewReader(body))
	rec := httptest.NewRecorder()

	value, err := rt.extractDiscriminator(rec, req, "kind")
	if err != nil {
		t.Fatalf("extractDiscriminator: %v", err)
	}
	if value != "KB" {
		t.Fatalf("discriminator value = %q; want KB", value)
	}

	// The body must be restored byte-for-byte for the strict handler.
	restored, err := readAllBody(req)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if restored != body {
		t.Fatalf("restored body = %q; want %q", restored, body)
	}
	if req.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength = %d; want %d", req.ContentLength, len(body))
	}
	if req.GetBody == nil {
		t.Fatal("GetBody not restored")
	}
}

func TestExtractDiscriminatorAbsentFailsClosed(t *testing.T) {
	spec, policy, _ := compileSynthetic(t, conditionalSpecYAML)
	rt := newRT(t, spec, policy, DefaultDenyRegistry(), nil)

	req := httptest.NewRequest(http.MethodPost, "/c", strings.NewReader(`{"pad":"x"}`))
	rec := httptest.NewRecorder()
	if _, err := rt.extractDiscriminator(rec, req, "kind"); err == nil {
		t.Fatal("absent discriminator accepted")
	}
}

func TestExtractDiscriminatorNonObjectFailsClosed(t *testing.T) {
	spec, policy, _ := compileSynthetic(t, conditionalSpecYAML)
	rt := newRT(t, spec, policy, DefaultDenyRegistry(), nil)

	req := httptest.NewRequest(http.MethodPost, "/c", strings.NewReader(`[1,2,3]`))
	rec := httptest.NewRecorder()
	if _, err := rt.extractDiscriminator(rec, req, "kind"); err == nil {
		t.Fatal("non-object body accepted")
	}
}

func readAllBody(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	defer r.Body.Close()
	b := new(strings.Builder)
	_, err := io.Copy(b, r.Body)
	return b.String(), err
}

// --- SOL-M4.2-002: authenticated bindings ---

// resultAuthenticator is a test double that returns a fixed result, for
// exercising invalid/mismatched success bindings.
type resultAuthenticator struct {
	kind   authpolicy.CredentialKind
	result AuthenticationResult
}

func (a resultAuthenticator) Kind() authpolicy.CredentialKind { return a.kind }
func (a resultAuthenticator) Authenticate(context.Context, *Credential) AuthenticationResult {
	return a.result
}

func TestAuthenticatedResultRequiresBinding(t *testing.T) {
	spec, policy, op := compileSynthetic(t, orSpecYAML)
	registry, err := NewRegistry(
		resultAuthenticator{kind: authpolicy.CredentialKindHumanOIDC, result: AuthenticationResult{Decision: DecisionAuthenticated}},
		acceptDevice(),
	)
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, nil)
	_, err = rt.authenticate(bearerRequest(t, "tok"), op)
	wantErrorKind(t, err, errorKindInvalidBinding)
}

func TestBindingKindMismatchFailsClosed(t *testing.T) {
	spec, policy, op := compileSynthetic(t, orSpecYAML)
	admin, err := NewAdminOIDCBinding("issuer", "subject")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(
		resultAuthenticator{
			kind: authpolicy.CredentialKindHumanOIDC,
			// Success binding claims a DIFFERENT kind than the authenticator.
			result: AuthenticationResult{Decision: DecisionAuthenticated, Binding: admin},
		},
		acceptDevice(),
	)
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, nil)
	_, err = rt.authenticate(bearerRequest(t, "tok"), op)
	wantErrorKind(t, err, errorKindInvalidBinding)
}

func TestContextExposesPerKindBinding(t *testing.T) {
	spec, policy, op := compileSynthetic(t, andSpecYAML)
	registry, err := NewRegistry(acceptBearer(authpolicy.CredentialKindHumanOIDC, "tok"), acceptDevice())
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, presentDevice())
	ac, err := rt.authenticate(bearerRequest(t, "tok"), op)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	human, ok := ac.Binding(authpolicy.CredentialKindHumanOIDC)
	oidc, isOIDC := human.OIDCIdentity()
	if !ok || !isOIDC || oidc.Issuer != "test-issuer" || oidc.Subject != "test-subject-human" {
		t.Fatalf("HumanOIDC binding = %+v (ok=%v, isOIDC=%v)", oidc, ok, isOIDC)
	}
	if _, wrong := human.DeviceMTLS(); wrong {
		t.Fatal("HumanOIDC binding must not expose a DeviceMTLS variant")
	}
	device, ok := ac.Binding(authpolicy.CredentialKindDeviceMTLS)
	dm, isDM := device.DeviceMTLS()
	if !ok || !isDM || dm.DeviceID != "test-device-id" || dm.CertificateID != "test-certificate-id" || dm.IssuedForEnrollmentID != "test-enrollment-id" {
		t.Fatalf("DeviceMTLS binding = %+v (ok=%v, isDM=%v)", dm, ok, isDM)
	}
	if _, wrong := device.OIDCIdentity(); wrong {
		t.Fatal("DeviceMTLS binding must not expose an OIDC variant")
	}
	if _, ok := ac.Binding(authpolicy.CredentialKindAdminOIDC); ok {
		t.Fatal("AdminOIDC must not have a binding")
	}
}

func TestBindingDoesNotRetainCredentialSecret(t *testing.T) {
	const secret = "secret-bearer-token-0000"
	spec, policy, op := compileSynthetic(t, orSpecYAML)
	registry, err := NewRegistry(
		BearerTestAuthenticator{
			KindValue: authpolicy.CredentialKindHumanOIDC,
			Decide: func(token string) Decision {
				if token == secret {
					return DecisionAuthenticated
				}
				return DecisionRejected
			},
		},
		acceptDevice(),
	)
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, nil)
	ac, err := rt.authenticate(bearerRequest(t, secret), op)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	b, ok := ac.Binding(authpolicy.CredentialKindHumanOIDC)
	if !ok {
		t.Fatal("missing binding")
	}
	// The typed OIDC binding carries issuer/subject only; the raw token is not
	// recoverable through any typed accessor or context accessor.
	oidc, isOIDC := b.OIDCIdentity()
	if !isOIDC {
		t.Fatal("expected OIDC binding")
	}
	for _, field := range []string{oidc.Issuer, oidc.Subject} {
		if field == secret || strings.Contains(field, secret) {
			t.Fatal("raw credential recovered from a binding field")
		}
	}
	if _, isReq := b.RequestAccess(); isReq {
		t.Fatal("HumanOIDC binding must not expose a request-access variant")
	}
}

func TestContextBindingDefensiveImmutability(t *testing.T) {
	spec, policy, op := compileSynthetic(t, andSpecYAML)
	registry, err := NewRegistry(acceptBearer(authpolicy.CredentialKindHumanOIDC, "tok"), acceptDevice())
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, registry, presentDevice())
	ac, err := rt.authenticate(bearerRequest(t, "tok"), op)
	if err != nil {
		t.Fatal(err)
	}

	// Mutating the returned slice must not affect internal bindings.
	bindings := ac.Bindings()
	bindings[0] = Binding{}
	if len(ac.Bindings()) != 2 {
		t.Fatal("internal bindings mutated through accessor")
	}
}
