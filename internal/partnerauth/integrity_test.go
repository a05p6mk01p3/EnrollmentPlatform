package partnerauth

import "testing"

func TestValidateHumanAuthorizationsRejectsMissingPrincipalID(t *testing.T) {
	_, err := validateHumanAuthorizations(HumanAuthorizations{PrincipalID: ""})
	if err == nil {
		t.Fatal("missing principal_id must fail closed")
	}
	_, err = validateHumanAuthorizations(HumanAuthorizations{PrincipalID: "   "})
	if err == nil {
		t.Fatal("whitespace-only principal_id must fail closed")
	}
}

func TestValidateHumanAuthorizationsRejectsEmptyPartnerID(t *testing.T) {
	_, err := validateHumanAuthorizations(HumanAuthorizations{
		PrincipalID: "principal-123",
		Partners:    []PartnerAuthorization{{PartnerID: "", Scopes: []string{"device:preonboard"}}},
	})
	if err == nil {
		t.Fatal("empty partner_id must fail closed")
	}
}

func TestValidateHumanAuthorizationsRejectsEmptyScopeName(t *testing.T) {
	_, err := validateHumanAuthorizations(HumanAuthorizations{
		PrincipalID: "principal-123",
		Partners:    []PartnerAuthorization{{PartnerID: "P1", Scopes: []string{"device:preonboard", "  "}}},
	})
	if err == nil {
		t.Fatal("empty scope name must fail closed")
	}
}

func TestValidateHumanAuthorizationsRejectsContradictoryDuplicates(t *testing.T) {
	_, err := validateHumanAuthorizations(HumanAuthorizations{
		PrincipalID: "principal-123",
		Partners: []PartnerAuthorization{
			{PartnerID: "P1", Scopes: []string{"device:preonboard"}},
			{PartnerID: "P1", Scopes: []string{"device:approve"}},
		},
	})
	if err == nil {
		t.Fatal("contradictory duplicate partner entries must fail closed")
	}
}

func TestValidateHumanAuthorizationsCollapsesIdenticalDuplicates(t *testing.T) {
	got, err := validateHumanAuthorizations(HumanAuthorizations{
		PrincipalID: "principal-123",
		Partners: []PartnerAuthorization{
			{PartnerID: "P1", DisplayName: "Revenda A", Scopes: []string{"device:preonboard", "device:preonboard"}},
			{PartnerID: "P1", DisplayName: "Revenda A", Scopes: []string{"device:preonboard"}},
		},
	})
	if err != nil {
		t.Fatalf("identical duplicate entries must be harmless: %v", err)
	}
	if len(got.Partners) != 1 {
		t.Fatalf("partners = %d, want 1", len(got.Partners))
	}
	if len(got.Partners[0].Scopes) != 1 || got.Partners[0].Scopes[0] != "device:preonboard" {
		t.Fatalf("scopes = %v, want [device:preonboard]", got.Partners[0].Scopes)
	}
}

func TestValidateHumanAuthorizationsValidEmptyPartners(t *testing.T) {
	got, err := validateHumanAuthorizations(HumanAuthorizations{PrincipalID: "principal-123", Partners: nil})
	if err != nil {
		t.Fatalf("valid empty result must not fail: %v", err)
	}
	if got.PrincipalID != "principal-123" || len(got.Partners) != 0 {
		t.Fatalf("unexpected normalized set: %+v", got)
	}
}

// M5.2-CHATGPT-002: padded authoritative identifiers are malformed, never
// canonicalized into authority.
func TestValidateHumanAuthorizationsRejectsPaddedPartnerID(t *testing.T) {
	_, err := validateHumanAuthorizations(HumanAuthorizations{
		PrincipalID: "principal-123",
		Partners:    []PartnerAuthorization{{PartnerID: " P1 ", Scopes: []string{"device:preonboard"}}},
	})
	if err == nil {
		t.Fatal("partner_id with leading/trailing whitespace must fail closed, not be trimmed into authority")
	}
}

func TestValidateHumanAuthorizationsRejectsPaddedScope(t *testing.T) {
	_, err := validateHumanAuthorizations(HumanAuthorizations{
		PrincipalID: "principal-123",
		Partners:    []PartnerAuthorization{{PartnerID: "P1", Scopes: []string{" device:preonboard "}}},
	})
	if err == nil {
		t.Fatal("scope with leading/trailing whitespace must fail closed, not be trimmed into authority")
	}
}

func TestValidateTemporaryPrincipalAuthorizationIDMismatch(t *testing.T) {
	exp := nowPlusHours(t, 1)
	_, err := validateTemporaryPrincipalAuthorization("tp-1", TemporaryPrincipalAuthorization{
		TemporaryPrincipalID: "tp-2",
		PartnerID:            "P1",
		Scopes:               []string{"device:preonboard"},
		Status:               TemporaryPrincipalStatusActive,
		ExpiresAt:            &exp,
	})
	if err == nil {
		t.Fatal("resolved record id must match the authenticated id")
	}
}

func TestValidateTemporaryPrincipalAuthorizationRejectsUnknownStatus(t *testing.T) {
	exp := nowPlusHours(t, 1)
	_, err := validateTemporaryPrincipalAuthorization("tp-1", TemporaryPrincipalAuthorization{
		TemporaryPrincipalID: "tp-1",
		PartnerID:            "P1",
		Scopes:               []string{"device:preonboard"},
		Status:               TemporaryPrincipalStatus("PENDING"),
		ExpiresAt:            &exp,
	})
	if err == nil {
		t.Fatal("unknown status must fail closed")
	}
}

func TestValidateTemporaryPrincipalAuthorizationRejectsMissingExpiry(t *testing.T) {
	_, err := validateTemporaryPrincipalAuthorization("tp-1", TemporaryPrincipalAuthorization{
		TemporaryPrincipalID: "tp-1",
		PartnerID:            "P1",
		Scopes:               []string{"device:preonboard"},
		Status:               TemporaryPrincipalStatusActive,
	})
	if err == nil {
		t.Fatal("missing expires_at must fail closed")
	}
}

// M5.2-CHATGPT-002: padded Temporary Principal identifiers are malformed,
// never canonicalized into authority.
func TestValidateTemporaryPrincipalAuthorizationRejectsPaddedScope(t *testing.T) {
	exp := nowPlusHours(t, 1)
	_, err := validateTemporaryPrincipalAuthorization("tp-1", TemporaryPrincipalAuthorization{
		TemporaryPrincipalID: "tp-1",
		PartnerID:            "P1",
		Scopes:               []string{" device:preonboard "},
		Status:               TemporaryPrincipalStatusActive,
		ExpiresAt:            &exp,
	})
	if err == nil {
		t.Fatal("temporary principal scope with leading/trailing whitespace must fail closed")
	}
}

func TestValidateTemporaryPrincipalAuthorizationRejectsPaddedPartnerID(t *testing.T) {
	exp := nowPlusHours(t, 1)
	_, err := validateTemporaryPrincipalAuthorization("tp-1", TemporaryPrincipalAuthorization{
		TemporaryPrincipalID: "tp-1",
		PartnerID:            " P1 ",
		Scopes:               []string{"device:preonboard"},
		Status:               TemporaryPrincipalStatusActive,
		ExpiresAt:            &exp,
	})
	if err == nil {
		t.Fatal("temporary principal partner_id with leading/trailing whitespace must fail closed")
	}
}
