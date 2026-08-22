package policy

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

// --- helpers ---

func loadCanonical(t *testing.T) *openapi3.T {
	t.Helper()
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	return spec
}

func cloneSpec(t *testing.T, spec *openapi3.T) *openapi3.T {
	t.Helper()
	data, err := spec.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	clone, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatalf("reload spec: %v", err)
	}
	return clone
}

func loadYAMLSpec(t *testing.T, yaml string) *openapi3.T {
	t.Helper()
	spec, err := openapi3.NewLoader().LoadFromData([]byte(yaml))
	if err != nil {
		t.Fatalf("load YAML spec: %v", err)
	}
	return spec
}

// mutateOperation applies fn to the operation with the given operationId.
func mutateOperation(t *testing.T, spec *openapi3.T, opID string, fn func(*openapi3.Operation)) {
	t.Helper()
	for _, pi := range spec.Paths.Map() {
		for _, m := range httpMethods {
			if op := pi.GetOperation(m); op != nil && op.OperationID == opID {
				fn(op)
				return
			}
		}
	}
	t.Fatalf("operation %q not found", opID)
}

// condObject returns the x-security-conditions extension of an operation as a
// map, assuming it is present and well-formed.
func condObject(op *openapi3.Operation) map[string]any {
	raw := op.Extensions["x-security-conditions"]
	m, _ := raw.(map[string]any)
	return m
}

// expectCompileError asserts that Compile fails with a *CompileError carrying
// the wanted reason.
func expectCompileError(t *testing.T, spec *openapi3.T, want Reason) {
	t.Helper()
	_, err := Compile(spec)
	if err == nil {
		t.Fatalf("Compile succeeded; want reason %q", want)
	}
	if !AsReason(err, want) {
		t.Fatalf("Compile error = %v; want reason %q", err, want)
	}
}

// renderAlternatives renders the base OR/AND alternatives of an operation in
// the same deterministic form used by OperationPolicy.String, without the
// conditional suffix.
func renderAlternatives(op *OperationPolicy) string {
	if op.NoApplicationCredential() {
		return "NO_APPLICATION_CREDENTIAL"
	}
	alts := op.Alternatives()
	parts := make([]string, len(alts))
	for i, a := range alts {
		parts[i] = a.String()
	}
	return strings.Join(parts, " OR ")
}

// assertConditional verifies the compiled conditional mapping for an
// operation.
func assertConditional(t *testing.T, p *Policy, opID, discriminator string, want map[string]CredentialKind) {
	t.Helper()
	op, ok := p.Operation(opID)
	if !ok {
		t.Fatalf("operation %q not compiled", opID)
	}
	c := op.Conditional()
	if c == nil {
		t.Fatalf("operation %q has no conditional security", opID)
	}
	if c.Discriminator() != discriminator {
		t.Errorf("operation %q discriminator = %q; want %q", opID, c.Discriminator(), discriminator)
	}
	cases := c.Cases()
	if len(cases) != len(want) {
		t.Fatalf("operation %q has %d cases; want %d", opID, len(cases), len(want))
	}
	for _, cs := range cases {
		wantKind, ok := want[cs.DiscriminatorValue()]
		if !ok {
			t.Errorf("operation %q has unexpected case %q", opID, cs.DiscriminatorValue())
			continue
		}
		req := cs.Requirement()
		if req.Len() != 1 || !req.hasKind(wantKind) {
			t.Errorf("operation %q case %q requirement = %v; want single %v", opID, cs.DiscriminatorValue(), req.Kinds(), wantKind)
		}
	}
}

// --- canonical matrix (§24, §25) ---

func TestCanonicalPolicyMatrix(t *testing.T) {
	spec := loadCanonical(t)
	p, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile canonical: %v", err)
	}

	if got := p.OperationCount(); got != 20 {
		t.Fatalf("OperationCount = %d; want 20", got)
	}

	want := map[string]string{
		"getMyAuthorizations":              "HumanOIDC",
		"createPreOnboardingRequest":       "HumanOIDC OR TemporaryPrincipalToken",
		"getPreOnboardingRequest":          "HumanOIDC OR RequestAccessToken",
		"createEnrollment":                 "RequestAccessToken OR DeviceMTLS",
		"getEnrollment":                    "EnrollmentAccessToken",
		"submitEnrollmentEvidence":         "EnrollmentAccessToken",
		"refreshEnrollmentChallenge":       "EnrollmentAccessToken",
		"getEnrollmentCertificate":         "EnrollmentAccessToken",
		"completeEnrollment":               "DeviceMTLS OR EnrollmentAccessToken",
		"getCurrentTrustBundle":            "NO_APPLICATION_CREDENTIAL",
		"adminListPreOnboardingRequests":   "AdminOIDC",
		"adminApprovePreOnboardingRequest": "AdminOIDC",
		"adminRejectPreOnboardingRequest":  "AdminOIDC",
		"adminCreateDeviceRebindRequest":   "AdminOIDC",
		"adminApproveDeviceRebindRequest":  "AdminOIDC",
		"adminCreateRevocationRequest":     "AdminOIDC",
		"adminCreateTemporaryPrincipal":    "AdminOIDC",
		"adminDisableTemporaryPrincipal":   "AdminOIDC",
		"adminGetRevocationRequest":        "AdminOIDC",
		"adminListRevocationCertificates":  "AdminOIDC",
	}
	if len(want) != 20 {
		t.Fatalf("expected matrix has %d entries; want 20", len(want))
	}

	seen := map[string]bool{}
	for _, op := range p.Operations() {
		if seen[op.OperationID()] {
			t.Errorf("duplicate operationId %q", op.OperationID())
		}
		seen[op.OperationID()] = true
	}

	for opID, wantBase := range want {
		op, ok := p.Operation(opID)
		if !ok {
			t.Errorf("operation %q not compiled", opID)
			continue
		}
		if got := renderAlternatives(op); got != wantBase {
			t.Errorf("operation %q base = %q; want %q", opID, got, wantBase)
		}
	}

	// Exactly two conditional policies.
	conditional := 0
	for _, op := range p.Operations() {
		if op.Conditional() != nil {
			conditional++
		}
	}
	if conditional != 2 {
		t.Fatalf("conditional policy count = %d; want 2", conditional)
	}

	assertConditional(t, p, "createEnrollment", "operation", map[string]CredentialKind{
		"INITIAL": CredentialKindRequestAccessToken,
		"RENEWAL": CredentialKindDeviceMTLS,
		"REKEY":   CredentialKindDeviceMTLS,
	})
	assertConditional(t, p, "completeEnrollment", "installation_status", map[string]CredentialKind{
		"INSTALLED": CredentialKindDeviceMTLS,
		"FAILED":    CredentialKindEnrollmentAccessToken,
	})

	// getCurrentTrustBundle is the only operation without application
	// credential.
	for _, op := range p.Operations() {
		if op.NoApplicationCredential() && op.OperationID() != "getCurrentTrustBundle" {
			t.Errorf("unexpected no-application-credential operation %q", op.OperationID())
		}
		if op.OperationID() == "getCurrentTrustBundle" && !op.NoApplicationCredential() {
			t.Errorf("getCurrentTrustBundle should be no-application-credential")
		}
	}
}

// --- synthetic OR/AND semantics (§26) ---

const syntheticSchemeHeader = `
components:
  securitySchemes:
    HumanOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
    AdminOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
    DeviceMTLS: {type: mutualTLS}
`

func syntheticSpec(t *testing.T, securityYAML string) *openapi3.T {
	t.Helper()
	yaml := "openapi: 3.1.0\ninfo: {title: synthetic, version: '1'}\npaths:\n  /x:\n    get:\n      operationId: op\n      responses:\n        '200':\n          description: ok\n      security:\n" + indentBlock(securityYAML) + syntheticSchemeHeader
	return loadYAMLSpec(t, yaml)
}

// indentBlock indents a multi-line YAML block by 8 spaces so it nests under
// the "security:" key at the operation level.
func indentBlock(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = "        " + l
	}
	return strings.Join(out, "\n") + "\n"
}

func TestSecurityOR(t *testing.T) {
	spec := syntheticSpec(t, "- HumanOIDC: []\n- AdminOIDC: []")
	p, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	op, _ := p.Operation("op")
	if got := renderAlternatives(op); got != "HumanOIDC OR AdminOIDC" {
		t.Fatalf("alternatives = %q; want %q", got, "HumanOIDC OR AdminOIDC")
	}
}

func TestSecurityAND(t *testing.T) {
	spec := syntheticSpec(t, "- HumanOIDC: []\n  DeviceMTLS: []")
	p, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	op, _ := p.Operation("op")
	alts := op.Alternatives()
	if len(alts) != 1 {
		t.Fatalf("alternatives count = %d; want 1", len(alts))
	}
	if got := alts[0].String(); got != "(DeviceMTLS AND HumanOIDC)" {
		t.Fatalf("conjunction = %q; want %q", got, "(DeviceMTLS AND HumanOIDC)")
	}
}

func TestSecurityOROfANDs(t *testing.T) {
	spec := syntheticSpec(t, "- HumanOIDC: []\n  DeviceMTLS: []\n- AdminOIDC: []")
	p, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	op, _ := p.Operation("op")
	if got := renderAlternatives(op); got != "(DeviceMTLS AND HumanOIDC) OR AdminOIDC" {
		t.Fatalf("alternatives = %q; want %q", got, "(DeviceMTLS AND HumanOIDC) OR AdminOIDC")
	}
}

// --- canonical spec immutability (§28) ---

func TestCompileDoesNotMutateCanonical(t *testing.T) {
	spec := loadCanonical(t)
	before, err := spec.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal before: %v", err)
	}
	if _, err := Compile(spec); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	after, err := spec.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("Compile mutated the canonical spec")
	}
}

// --- compiled policy immutability / concurrency (§29) ---

func TestCompiledPolicyImmutable(t *testing.T) {
	spec := loadCanonical(t)
	p, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	op, _ := p.Operation("createPreOnboardingRequest")

	// Mutating the returned alternatives slice must not affect internals.
	alts := op.Alternatives()
	alts[0] = Conjunction{}
	if got := op.Alternatives(); got[0].Len() == 0 {
		t.Fatal("internal alternatives mutated through accessor")
	}

	// Mutating the returned kinds slice must not affect internals.
	kinds := op.Alternatives()[0].Kinds()
	kinds[0] = CredentialKindDeviceMTLS
	if got := op.Alternatives()[0].Kinds()[0]; got != CredentialKindHumanOIDC {
		t.Fatal("internal conjunction kinds mutated through accessor")
	}
}

func TestCompiledPolicyConcurrentReads(t *testing.T) {
	spec := loadCanonical(t)
	p, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				for _, op := range p.Operations() {
					_ = op.Alternatives()
					_ = op.Conditional()
					_ = op.String()
				}
			}
		}()
	}
	wg.Wait()
}

// --- determinism (§30) ---

func TestCompileDeterminism(t *testing.T) {
	spec := loadCanonical(t)
	p1, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile #1: %v", err)
	}
	p2, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile #2: %v", err)
	}
	if p1.OperationCount() != p2.OperationCount() {
		t.Fatal("operation counts differ")
	}
	for _, op := range p1.Operations() {
		op2, ok := p2.Operation(op.OperationID())
		if !ok {
			t.Fatalf("operation %q missing from second compile", op.OperationID())
		}
		if op.String() != op2.String() {
			t.Fatalf("non-deterministic compile for %q:\n  %s\n  %s", op.OperationID(), op.String(), op2.String())
		}
	}
}

// --- security metadata mutations (§27) ---

func TestSecurityMetadataMutations(t *testing.T) {
	cases := []struct {
		name   string
		opID   string
		mutate func(*openapi3.Operation)
		want   Reason
	}{
		{
			name: "remove security field",
			opID: "getMyAuthorizations",
			mutate: func(op *openapi3.Operation) {
				op.Security = nil
			},
			want: ReasonNilSecurity,
		},
		{
			name: "public operation loses explicit empty security",
			opID: "getCurrentTrustBundle",
			mutate: func(op *openapi3.Operation) {
				op.Security = nil
			},
			want: ReasonNilSecurity,
		},
		{
			name: "empty security requirement object",
			opID: "getMyAuthorizations",
			mutate: func(op *openapi3.Operation) {
				op.Security = &openapi3.SecurityRequirements{{}}
			},
			want: ReasonEmptySecurityRequirement,
		},
		{
			name: "unknown scheme",
			opID: "getMyAuthorizations",
			mutate: func(op *openapi3.Operation) {
				op.Security = &openapi3.SecurityRequirements{{"BogusScheme": {}}}
			},
			want: ReasonUnknownScheme,
		},
		{
			name: "non-empty scopes",
			opID: "getMyAuthorizations",
			mutate: func(op *openapi3.Operation) {
				op.Security = &openapi3.SecurityRequirements{{"HumanOIDC": {"some.scope"}}}
			},
			want: ReasonNonEmptyScopes,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := cloneSpec(t, loadCanonical(t))
			mutateOperation(t, spec, tc.opID, tc.mutate)
			expectCompileError(t, spec, tc.want)
		})
	}
}

// TestUnresolvedScheme verifies that a scheme name that is one of the six
// contractual kinds but is not declared in components/securitySchemes fails
// with ReasonUnresolvedScheme (rather than being silently accepted).
func TestUnresolvedScheme(t *testing.T) {
	spec := cloneSpec(t, loadCanonical(t))
	delete(spec.Components.SecuritySchemes, "DeviceMTLS")
	mutateOperation(t, spec, "getMyAuthorizations", func(op *openapi3.Operation) {
		op.Security = &openapi3.SecurityRequirements{{"DeviceMTLS": {}}}
	})
	expectCompileError(t, spec, ReasonUnresolvedScheme)
}

// --- credential-kind swaps are reflected in the compiled policy (§27) ---

func TestCredentialKindSwapsDetected(t *testing.T) {
	cases := []struct {
		name   string
		opID   string
		mutate func(*openapi3.Operation)
		want   string
	}{
		{
			name: "HumanOIDC swapped to AdminOIDC",
			opID: "getMyAuthorizations",
			mutate: func(op *openapi3.Operation) {
				op.Security = &openapi3.SecurityRequirements{{"AdminOIDC": {}}}
			},
			want: "AdminOIDC",
		},
		{
			name: "RequestAccessToken swapped to EnrollmentAccessToken",
			opID: "getPreOnboardingRequest",
			mutate: func(op *openapi3.Operation) {
				op.Security = &openapi3.SecurityRequirements{{"EnrollmentAccessToken": {}}}
			},
			want: "EnrollmentAccessToken",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := cloneSpec(t, loadCanonical(t))
			mutateOperation(t, spec, tc.opID, tc.mutate)
			p, err := Compile(spec)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			op, _ := p.Operation(tc.opID)
			if got := renderAlternatives(op); got != tc.want {
				t.Fatalf("alternatives = %q; want %q", got, tc.want)
			}
		})
	}
}

// TestAuthenticatedOperationChangedToPublicDetected verifies that turning an
// authenticated operation into security: [] is reflected (and therefore
// detectable against the canonical matrix) rather than silently ignored.
func TestAuthenticatedOperationChangedToPublicDetected(t *testing.T) {
	spec := cloneSpec(t, loadCanonical(t))
	mutateOperation(t, spec, "getMyAuthorizations", func(op *openapi3.Operation) {
		op.Security = &openapi3.SecurityRequirements{}
	})
	p, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	op, _ := p.Operation("getMyAuthorizations")
	if !op.NoApplicationCredential() {
		t.Fatal("mutation to security: [] was not reflected in compiled policy")
	}
}

// --- x-security-conditions mutations (§27) ---

func TestConditionalSecurityMutations(t *testing.T) {
	cases := []struct {
		name   string
		opID   string
		mutate func(*openapi3.Operation)
		want   Reason
	}{
		{
			name: "remove discriminator",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				delete(condObject(op), "discriminator")
			},
			want: ReasonConditionalMalformed,
		},
		{
			name: "empty discriminator",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				condObject(op)["discriminator"] = ""
			},
			want: ReasonConditionalMalformed,
		},
		{
			name: "change discriminator name",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				condObject(op)["discriminator"] = "something_else"
			},
			want: ReasonConditionalDiscriminatorMismatch,
		},
		{
			name: "remove cases",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				delete(condObject(op), "cases")
			},
			want: ReasonConditionalMalformed,
		},
		{
			name: "empty cases",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				condObject(op)["cases"] = map[string]any{}
			},
			want: ReasonConditionalMalformed,
		},
		{
			name: "remove a case",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				cases := condObject(op)["cases"].(map[string]any)
				delete(cases, "REKEY")
			},
			want: ReasonConditionalCaseMismatch,
		},
		{
			name: "add unknown case",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				cases := condObject(op)["cases"].(map[string]any)
				cases["BOGUS"] = map[string]any{"requiredSecurityScheme": "DeviceMTLS"}
			},
			want: ReasonConditionalCaseMismatch,
		},
		{
			name: "change requiredSecurityScheme to unknown scheme",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				cases := condObject(op)["cases"].(map[string]any)
				cases["INITIAL"].(map[string]any)["requiredSecurityScheme"] = "BogusScheme"
			},
			want: ReasonUnknownScheme,
		},
		{
			name: "case scheme not admitted by base security",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				cases := condObject(op)["cases"].(map[string]any)
				cases["INITIAL"].(map[string]any)["requiredSecurityScheme"] = "EnrollmentAccessToken"
			},
			want: ReasonConditionalSchemeNotSingletonAlternative,
		},
		{
			name: "remove requiredSecurityScheme",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				cases := condObject(op)["cases"].(map[string]any)
				delete(cases["INITIAL"].(map[string]any), "requiredSecurityScheme")
			},
			want: ReasonConditionalMalformed,
		},
		{
			name: "remove enforcement",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				delete(condObject(op), "enforcement")
			},
			want: ReasonConditionalEnforcement,
		},
		{
			name: "change enforcement",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				condObject(op)["enforcement"] = "OPTIONAL"
			},
			want: ReasonConditionalEnforcement,
		},
		{
			name: "unknown top-level field",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				condObject(op)["bogusField"] = "x"
			},
			want: ReasonConditionalUnknownField,
		},
		{
			name: "unknown case field",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				cases := condObject(op)["cases"].(map[string]any)
				cases["INITIAL"].(map[string]any)["bogusField"] = "x"
			},
			want: ReasonConditionalUnknownField,
		},
		{
			name: "remove entire x-security-conditions (createEnrollment)",
			opID: "createEnrollment",
			mutate: func(op *openapi3.Operation) {
				delete(op.Extensions, "x-security-conditions")
			},
			want: ReasonConditionalMissing,
		},
		{
			name: "remove entire x-security-conditions (completeEnrollment)",
			opID: "completeEnrollment",
			mutate: func(op *openapi3.Operation) {
				delete(op.Extensions, "x-security-conditions")
			},
			want: ReasonConditionalMissing,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := cloneSpec(t, loadCanonical(t))
			mutateOperation(t, spec, tc.opID, tc.mutate)
			expectCompileError(t, spec, tc.want)
		})
	}
}

// --- typed errors (§21) ---

func TestCompileErrorIsTyped(t *testing.T) {
	spec := cloneSpec(t, loadCanonical(t))
	mutateOperation(t, spec, "getMyAuthorizations", func(op *openapi3.Operation) {
		op.Security = &openapi3.SecurityRequirements{{"BogusScheme": {}}}
	})
	_, err := Compile(spec)
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *CompileError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *CompileError", err)
	}
	if ce.Reason != ReasonUnknownScheme {
		t.Fatalf("Reason = %q; want %q", ce.Reason, ReasonUnknownScheme)
	}
	if ce.OperationID != "getMyAuthorizations" {
		t.Fatalf("OperationID = %q; want %q", ce.OperationID, "getMyAuthorizations")
	}
	if ce.Method == "" || ce.Path == "" {
		t.Fatalf("missing method/path context: %+v", ce)
	}
}

// --- SOL-M4.1-001: conditional scheme must be a complete singleton base
// alternative ---

// syntheticConditionalSpec builds a minimal spec whose operation has a
// discriminated request body (propertyName "kind", one mapping "KA") and an
// x-security-conditions extension requiring the given scheme for case "KA".
func syntheticConditionalSpec(t *testing.T, securityYAML, requiredScheme string) *openapi3.T {
	t.Helper()
	yaml := "openapi: 3.1.0\ninfo: {title: synthetic, version: '1'}\npaths:\n  /x:\n    post:\n      operationId: condOp\n      requestBody:\n        required: true\n        content:\n          application/json:\n            schema:\n              oneOf:\n                - $ref: '#/components/schemas/KA'\n              discriminator:\n                propertyName: kind\n                mapping:\n                  KA: '#/components/schemas/KA'\n      responses:\n        '200':\n          description: ok\n      security:\n" + indentBlock(securityYAML) +
		"      x-security-conditions:\n        discriminator: kind\n        cases:\n          KA:\n            requiredSecurityScheme: " + requiredScheme + "\n        enforcement: MANDATORY_SERVER_POLICY_AND_CONTRACT_TEST\n" +
		syntheticSchemeHeader + "  schemas:\n    KA:\n      type: object\n      properties:\n        kind:\n          type: string\n"
	return loadYAMLSpec(t, yaml)
}

// TestConditionalSchemeInsideANDOnlyFails proves that a singular
// requiredSecurityScheme is NOT accepted merely because it is a member of a
// larger AND conjunction: DeviceMTLS appears only inside
// (HumanOIDC AND DeviceMTLS), never as a complete singleton alternative.
func TestConditionalSchemeInsideANDOnlyFails(t *testing.T) {
	spec := syntheticConditionalSpec(t,
		"- HumanOIDC: []\n  DeviceMTLS: []\n- AdminOIDC: []",
		"DeviceMTLS")
	expectCompileError(t, spec, ReasonConditionalSchemeNotSingletonAlternative)
}

// TestConditionalSchemeWithSingletonAlternativeSucceeds proves the same
// condition succeeds when the mandated scheme exists as a complete singleton
// alternative of the base security, even though it also appears inside an
// AND conjunction.
func TestConditionalSchemeWithSingletonAlternativeSucceeds(t *testing.T) {
	spec := syntheticConditionalSpec(t,
		"- DeviceMTLS: []\n- HumanOIDC: []\n  DeviceMTLS: []",
		"DeviceMTLS")
	p, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	op, ok := p.Operation("condOp")
	if !ok {
		t.Fatal("operation condOp not compiled")
	}
	c := op.Conditional()
	if c == nil {
		t.Fatal("expected conditional security")
	}
	req, ok := c.RequirementFor("KA")
	if !ok || req.Len() != 1 || !req.hasKind(CredentialKindDeviceMTLS) {
		t.Fatalf("case KA requirement = %v; want single DeviceMTLS", req.Kinds())
	}
}

// --- SOL-M4.1-002: structural validation of recognized scheme definitions ---

func TestSchemeStructureMutations(t *testing.T) {
	cases := []struct {
		name   string
		scheme string
		mutate func(*openapi3.SecurityScheme)
	}{
		{"HumanOIDC type changed", "HumanOIDC", func(ss *openapi3.SecurityScheme) { ss.Type = "mutualTLS" }},
		{"HumanOIDC http scheme changed", "HumanOIDC", func(ss *openapi3.SecurityScheme) { ss.Scheme = "basic" }},
		{"HumanOIDC bearerFormat changed", "HumanOIDC", func(ss *openapi3.SecurityScheme) { ss.BearerFormat = "opaque" }},
		{"AdminOIDC bearerFormat changed", "AdminOIDC", func(ss *openapi3.SecurityScheme) { ss.BearerFormat = "opaque" }},
		{"AdminOIDC scheme removed", "AdminOIDC", func(ss *openapi3.SecurityScheme) { ss.Scheme = "" }},
		{"TemporaryPrincipalToken type changed", "TemporaryPrincipalToken", func(ss *openapi3.SecurityScheme) { ss.Type = "mutualTLS" }},
		{"TemporaryPrincipalToken scheme changed", "TemporaryPrincipalToken", func(ss *openapi3.SecurityScheme) { ss.Scheme = "digest" }},
		{"RequestAccessToken bearerFormat changed", "RequestAccessToken", func(ss *openapi3.SecurityScheme) { ss.BearerFormat = "JWT" }},
		{"EnrollmentAccessToken bearerFormat changed", "EnrollmentAccessToken", func(ss *openapi3.SecurityScheme) { ss.BearerFormat = "JWT" }},
		{"EnrollmentAccessToken type changed", "EnrollmentAccessToken", func(ss *openapi3.SecurityScheme) { ss.Type = "apiKey" }},
		{"DeviceMTLS type changed", "DeviceMTLS", func(ss *openapi3.SecurityScheme) { ss.Type = "http" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := cloneSpec(t, loadCanonical(t))
			ssr := spec.Components.SecuritySchemes[tc.scheme]
			if ssr == nil || ssr.Value == nil {
				t.Fatalf("scheme %q not resolvable in cloned spec", tc.scheme)
			}
			tc.mutate(ssr.Value)
			expectCompileError(t, spec, ReasonSchemeStructureMismatch)
		})
	}
}

// TestBearerSchemeComparisonCaseInsensitive proves that the HTTP auth scheme
// comparison honors RFC 7235 case-insensitivity: "Bearer" is accepted where
// "bearer" is contracted.
func TestBearerSchemeComparisonCaseInsensitive(t *testing.T) {
	spec := cloneSpec(t, loadCanonical(t))
	ssr := spec.Components.SecuritySchemes["HumanOIDC"]
	if ssr == nil || ssr.Value == nil {
		t.Fatal("HumanOIDC not resolvable in cloned spec")
	}
	ssr.Value.Scheme = "Bearer"
	if _, err := Compile(spec); err != nil {
		t.Fatalf("Compile with capitalized bearer scheme: %v", err)
	}
}

// TestTemporaryPrincipalTokenBearerFormatNotValidated proves that no
// JWT/opaque/concrete verification mechanism is inferred or required for
// TemporaryPrincipalToken: adding a bearerFormat must not be a structural
// failure, because M4.1 does not define that mechanism (OPEN-003).
func TestTemporaryPrincipalTokenBearerFormatNotValidated(t *testing.T) {
	spec := cloneSpec(t, loadCanonical(t))
	ssr := spec.Components.SecuritySchemes["TemporaryPrincipalToken"]
	if ssr == nil || ssr.Value == nil {
		t.Fatal("TemporaryPrincipalToken not resolvable in cloned spec")
	}
	ssr.Value.BearerFormat = "whatever-the-future-mechanism-is"
	if _, err := Compile(spec); err != nil {
		t.Fatalf("Compile: %v", err)
	}
}

// --- SOL-M4.1-003: missing/empty operationId fails closed ---

func TestMissingOperationIDMutations(t *testing.T) {
	cases := []struct {
		name  string
		opID  string
		newID string
	}{
		{"operationId removed", "getMyAuthorizations", ""},
		{"operationId whitespace-only", "getMyAuthorizations", "   "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := cloneSpec(t, loadCanonical(t))
			mutateOperation(t, spec, tc.opID, func(op *openapi3.Operation) {
				op.OperationID = tc.newID
			})
			expectCompileError(t, spec, ReasonMissingOperationID)
		})
	}
}

// TestOperationIDIsNotRewritten proves that a valid operationId is used
// verbatim: the compiler does not normalize casing or otherwise rewrite
// operationIds. The operation is indexed under the exact declared value.
func TestOperationIDIsNotRewritten(t *testing.T) {
	spec := cloneSpec(t, loadCanonical(t))
	mutateOperation(t, spec, "getMyAuthorizations", func(op *openapi3.Operation) {
		op.OperationID = "getMyAuthOrIzations" // mixed case; must be preserved verbatim
	})
	p, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, ok := p.Operation("getMyAuthOrIzations"); !ok {
		t.Fatal("operation indexed under a different operationId than declared")
	}
	if _, ok := p.Operation("getMyAuthorizations"); ok {
		t.Fatal("compiler normalized or aliased the operationId casing")
	}
}
