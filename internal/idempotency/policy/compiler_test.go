package policy_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/policy"
)

func canonicalSpec(t testing.TB) *openapi3.T {
	t.Helper()
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	return spec
}

func TestCompileCanonicalSpecDiscoversExactlyElevenIdempotentOperations(t *testing.T) {
	spec := canonicalSpec(t)
	p, err := policy.Compile(spec)
	if err != nil {
		t.Fatalf("Compile canonical: %v", err)
	}

	if p.OperationCount() != 11 {
		t.Fatalf("OperationCount = %d, want 11", p.OperationCount())
	}

	want := map[string]struct {
		method string
		route  string
	}{
		"createPreOnboardingRequest":       {"POST", "/v1/pre-onboarding-requests"},
		"createEnrollment":                 {"POST", "/v1/enrollments"},
		"refreshEnrollmentChallenge":       {"POST", "/v1/enrollments/{id}/challenge:refresh"},
		"completeEnrollment":               {"POST", "/v1/enrollments/{id}/complete"},
		"adminApprovePreOnboardingRequest": {"POST", "/v1/admin/pre-onboarding-requests/{id}/approve"},
		"adminRejectPreOnboardingRequest":  {"POST", "/v1/admin/pre-onboarding-requests/{id}/reject"},
		"adminCreateDeviceRebindRequest":   {"POST", "/v1/admin/devices/{id}/rebind-requests"},
		"adminApproveDeviceRebindRequest":  {"POST", "/v1/admin/device-rebind-requests/{id}/approve"},
		"adminCreateRevocationRequest":     {"POST", "/v1/admin/certificates/{id}/revocations"},
		"adminCreateTemporaryPrincipal":    {"POST", "/v1/admin/temporary-principals"},
		"adminDisableTemporaryPrincipal":   {"POST", "/v1/admin/temporary-principals/{id}/disable"},
	}

	seen := make(map[string]bool)
	for _, op := range p.Operations() {
		expected, ok := want[op.OperationID()]
		if !ok {
			t.Errorf("unexpected idempotent operation %q", op.OperationID())
			continue
		}
		seen[op.OperationID()] = true
		if !op.KeyRequired() {
			t.Errorf("op %s: KeyRequired = false, want true", op.OperationID())
		}
		if op.Method() != expected.method {
			t.Errorf("op %s: Method = %q, want %q", op.OperationID(), op.Method(), expected.method)
		}
		if op.Route() != expected.route {
			t.Errorf("op %s: Route = %q, want %q", op.OperationID(), op.Route(), expected.route)
		}
	}

	if len(seen) != len(want) {
		t.Fatalf("discovered %d distinct operations, want %d", len(seen), len(want))
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("missing idempotent operation %q", id)
		}
	}

	// Non-idempotent operations must not be part of the policy.
	if _, ok := p.Operation("getPreOnboardingRequest"); ok {
		t.Errorf("getPreOnboardingRequest should not be part of the idempotency policy")
	}
}

func TestCompileCanonicalSecretReplayDiscovery(t *testing.T) {
	spec := canonicalSpec(t)
	p, err := policy.Compile(spec)
	if err != nil {
		t.Fatalf("Compile canonical: %v", err)
	}

	if p.SecretReplayCount() != 2 {
		t.Fatalf("SecretReplayCount = %d, want 2", p.SecretReplayCount())
	}

	want := map[string]policy.SecretReplay{
		"createPreOnboardingRequest": {
			SecretField:           "request_access_token",
			Mechanism:             "encrypted-idempotency-replay-capsule",
			SameSecretRequired:    true,
			ActiveVerifierStorage: "non-reversible",
			CapsulePurpose:        "response-loss-recovery-only",
		},
		"createEnrollment": {
			SecretField:           "enrollment_access_token",
			Mechanism:             "encrypted-idempotency-replay-capsule",
			SameSecretRequired:    true,
			ActiveVerifierStorage: "non-reversible",
			CapsulePurpose:        "response-loss-recovery-only",
		},
	}

	for id, wantMeta := range want {
		op, ok := p.Operation(id)
		if !ok {
			t.Fatalf("missing operation %q", id)
		}
		if !op.IsSecretReplay() {
			t.Fatalf("op %s: IsSecretReplay = false, want true", id)
		}
		got, ok := op.SecretReplayMetadata()
		if !ok {
			t.Fatalf("op %s: SecretReplayMetadata ok=false", id)
		}
		if got != wantMeta {
			t.Errorf("op %s: metadata = %+v, want %+v", id, got, wantMeta)
		}
	}

	// Non-originator idempotent operations must not carry secret-replay metadata.
	for _, op := range p.Operations() {
		if op.IsSecretReplay() {
			if _, ok := want[op.OperationID()]; !ok {
				t.Errorf("op %s unexpectedly has secret-replay metadata", op.OperationID())
			}
		}
	}
}

func mutateSpec(t testing.TB, mutate func(doc map[string]any)) *openapi3.T {
	t.Helper()
	spec := canonicalSpec(t)
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	doc := map[string]any{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	mutate(doc)
	mutatedData, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal mutated: %v", err)
	}
	mutated, err := openapi3.NewLoader().LoadFromData(mutatedData)
	if err != nil {
		t.Fatalf("load mutated: %v", err)
	}
	return mutated
}

func postOperation(doc map[string]any, path string) map[string]any {
	return doc["paths"].(map[string]any)[path].(map[string]any)["post"].(map[string]any)
}

func removeIdempotencyKeyParam(op map[string]any) {
	params := op["parameters"].([]any)
	kept := make([]any, 0, len(params))
	for _, p := range params {
		pm, ok := p.(map[string]any)
		if ok && pm["$ref"] == "#/components/parameters/IdempotencyKey" {
			continue
		}
		kept = append(kept, p)
	}
	op["parameters"] = kept
}

func assertCompileReason(t *testing.T, err error, want policy.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected compile error with reason %s, got nil", want)
	}
	var ce *policy.CompileError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *policy.CompileError, got %T: %v", err, err)
	}
	if ce.Reason != want {
		t.Fatalf("reason = %s, want %s (err: %v)", ce.Reason, want, ce)
	}
}

func TestCompileNilSpecFails(t *testing.T) {
	if _, err := policy.Compile(nil); err == nil {
		t.Fatal("expected error on nil spec, got nil")
	}
}

func TestCompileMalformedFixturesFailClosed(t *testing.T) {
	t.Run("secret replay without Idempotency-Key", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			op := postOperation(doc, "/v1/pre-onboarding-requests")
			removeIdempotencyKeyParam(op)
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonSecretReplayWithoutIdempotencyKey)
	})

	t.Run("Idempotency-Key declared inline instead of canonical component", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			op := postOperation(doc, "/v1/enrollments")
			params := op["parameters"].([]any)
			for i, p := range params {
				pm, ok := p.(map[string]any)
				if ok && pm["$ref"] == "#/components/parameters/IdempotencyKey" {
					params[i] = map[string]any{
						"name":     "Idempotency-Key",
						"in":       "header",
						"required": true,
						"schema":   map[string]any{"type": "string"},
					}
				}
			}
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedIdempotencyKey)
	})

	t.Run("duplicate Idempotency-Key", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			op := postOperation(doc, "/v1/enrollments")
			op["parameters"] = append(op["parameters"].([]any),
				map[string]any{"$ref": "#/components/parameters/IdempotencyKey"})
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedIdempotencyKey)
	})

	t.Run("IdempotencyKey component not required", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			comp := doc["components"].(map[string]any)["parameters"].(map[string]any)["IdempotencyKey"].(map[string]any)
			comp["required"] = false
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedIdempotencyKey)
	})

	t.Run("secret replay unknown field", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			ext := postOperation(doc, "/v1/enrollments")["x-idempotent-secret-replay"].(map[string]any)
			ext["inventedField"] = true
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedSecretReplay)
	})

	t.Run("secret replay missing secretField", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			ext := postOperation(doc, "/v1/enrollments")["x-idempotent-secret-replay"].(map[string]any)
			delete(ext, "secretField")
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedSecretReplay)
	})

	t.Run("secret replay wrong mechanism", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			ext := postOperation(doc, "/v1/enrollments")["x-idempotent-secret-replay"].(map[string]any)
			ext["mechanism"] = "plaintext-cache"
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonSecretReplayValueMismatch)
	})

	t.Run("secret replay sameSecretRequired false", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			ext := postOperation(doc, "/v1/enrollments")["x-idempotent-secret-replay"].(map[string]any)
			ext["sameSecretRequired"] = false
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonSecretReplayValueMismatch)
	})

	t.Run("secret replay wrong activeVerifierStorage", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			ext := postOperation(doc, "/v1/enrollments")["x-idempotent-secret-replay"].(map[string]any)
			ext["activeVerifierStorage"] = "reversible"
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonSecretReplayValueMismatch)
	})

	t.Run("secret replay wrong capsulePurpose", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			ext := postOperation(doc, "/v1/enrollments")["x-idempotent-secret-replay"].(map[string]any)
			ext["capsulePurpose"] = "authentication"
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonSecretReplayValueMismatch)
	})

	t.Run("secret replay not an object", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			postOperation(doc, "/v1/enrollments")["x-idempotent-secret-replay"] = "encrypted"
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedSecretReplay)
	})

	t.Run("path-level non-canonical Idempotency-Key", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			item := paths["/v1/admin/revocation-requests/{id}"].(map[string]any)
			item["parameters"] = []any{
				map[string]any{
					"name":     "Idempotency-Key",
					"in":       "header",
					"required": true,
					"schema":   map[string]any{"type": "string"},
				},
			}
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedIdempotencyKey)
	})

	t.Run("case-insensitive header-name equivalent", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			op := postOperation(doc, "/v1/enrollments")
			op["parameters"] = append(op["parameters"].([]any),
				map[string]any{
					"name":     "idempotency-key",
					"in":       "header",
					"required": true,
					"schema":   map[string]any{"type": "string"},
				})
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedIdempotencyKey)
	})
}

func TestPathLevelCanonicalIdempotencyKeyHonoredByEffectiveSemantics(t *testing.T) {
	// A semantically relevant declaration must never disappear silently: a
	// path-item-level canonical Idempotency-Key applies to every operation on
	// the path per OpenAPI effective parameter semantics.
	spec := mutateSpec(t, func(doc map[string]any) {
		paths := doc["paths"].(map[string]any)
		item := paths["/v1/pre-onboarding-requests/{id}"].(map[string]any)
		item["parameters"] = []any{
			map[string]any{"$ref": "#/components/parameters/IdempotencyKey"},
		}
	})
	p, err := policy.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if p.OperationCount() != 12 {
		t.Fatalf("OperationCount = %d, want 12 (11 + path-level getPreOnboardingRequest)", p.OperationCount())
	}
	op, ok := p.Operation("getPreOnboardingRequest")
	if !ok {
		t.Fatal("getPreOnboardingRequest should now be idempotent via path-level parameter")
	}
	if !op.KeyRequired() {
		t.Fatal("getPreOnboardingRequest KeyRequired = false, want true")
	}
}

func replaceIdempotencyKeyParam(op map[string]any, replacement map[string]any) {
	params := op["parameters"].([]any)
	for i, p := range params {
		pm, ok := p.(map[string]any)
		if ok && pm["$ref"] == "#/components/parameters/IdempotencyKey" {
			params[i] = replacement
		}
	}
}

func TestIdempotencyKeyEffectiveOverrideAndLocationFailClosed(t *testing.T) {
	t.Run("path-level canonical + operation-level canonical override compiles", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			item := paths["/v1/pre-onboarding-requests"].(map[string]any)
			item["parameters"] = []any{
				map[string]any{"$ref": "#/components/parameters/IdempotencyKey"},
			}
		})
		p, err := policy.Compile(spec)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if p.OperationCount() != 11 {
			t.Fatalf("OperationCount = %d, want 11 (override yields one effective key, no new operations)", p.OperationCount())
		}
		op, ok := p.Operation("createPreOnboardingRequest")
		if !ok || !op.KeyRequired() {
			t.Fatalf("createPreOnboardingRequest must remain idempotent after override; ok=%v keyRequired=%v", ok, op.KeyRequired())
		}
	})

	t.Run("path-level canonical + operation-level malformed override fails closed", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			item := paths["/v1/pre-onboarding-requests"].(map[string]any)
			item["parameters"] = []any{
				map[string]any{"$ref": "#/components/parameters/IdempotencyKey"},
			}
			op := postOperation(doc, "/v1/pre-onboarding-requests")
			replaceIdempotencyKeyParam(op, map[string]any{
				"name":     "Idempotency-Key",
				"in":       "header",
				"required": true,
				"schema":   map[string]any{"type": "string"},
			})
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedIdempotencyKey)
	})

	t.Run("wrong-location Idempotency-Key on ordinary idempotent operation fails closed", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			op := postOperation(doc, "/v1/enrollments/{id}/challenge:refresh")
			replaceIdempotencyKeyParam(op, map[string]any{
				"name":     "Idempotency-Key",
				"in":       "query",
				"required": true,
				"schema":   map[string]any{"type": "string"},
			})
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedIdempotencyKey)
	})

	t.Run("canonical ref with inconsistent resolved location fails closed", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			comp := doc["components"].(map[string]any)["parameters"].(map[string]any)["IdempotencyKey"].(map[string]any)
			comp["in"] = "query"
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedIdempotencyKey)
	})
}
