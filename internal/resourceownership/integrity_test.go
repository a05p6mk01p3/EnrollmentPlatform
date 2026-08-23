package resourceownership_test

import (
	"testing"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

func TestValidateOwnershipResult(t *testing.T) {
	tests := []struct {
		name        string
		requestedID string
		raw         resourceownership.OwnershipResult
		wantErr     bool
	}{
		{
			name:        "valid FOUND exact match",
			requestedID: "por-123",
			raw:         resourceownership.OwnershipFound("por-123", "P1"),
			wantErr:     false,
		},
		{
			name:        "valid NOT_FOUND",
			requestedID: "por-123",
			raw:         resourceownership.OwnershipNotFound(),
			wantErr:     false,
		},
		{
			name:        "empty requested ID",
			requestedID: "",
			raw:         resourceownership.OwnershipFound("por-123", "P1"),
			wantErr:     true,
		},
		{
			name:        "padded requested ID",
			requestedID: " por-123 ",
			raw:         resourceownership.OwnershipFound("por-123", "P1"),
			wantErr:     true,
		},
		{
			name:        "FOUND with empty resource ID",
			requestedID: "por-123",
			raw:         resourceownership.OwnershipFound("", "P1"),
			wantErr:     true,
		},
		{
			name:        "FOUND with padded resource ID",
			requestedID: "por-123",
			raw:         resourceownership.OwnershipFound(" por-123 ", "P1"),
			wantErr:     true,
		},
		{
			name:        "FOUND with mismatched resource ID",
			requestedID: "por-123",
			raw:         resourceownership.OwnershipFound("por-456", "P1"),
			wantErr:     true,
		},
		{
			name:        "FOUND with empty partner ID",
			requestedID: "por-123",
			raw:         resourceownership.OwnershipFound("por-123", ""),
			wantErr:     true,
		},
		{
			name:        "FOUND with padded partner ID",
			requestedID: "por-123",
			raw:         resourceownership.OwnershipFound("por-123", " P1 "),
			wantErr:     true,
		},
		{
			name:        "contradictory NOT_FOUND with resource ID",
			requestedID: "por-123",
			raw: resourceownership.OwnershipResult{
				Status: resourceownership.OwnershipStatusNotFound,
				Ownership: resourceownership.ResourceOwnership{
					ResourceID: "por-123",
				},
			},
			wantErr: true,
		},
		{
			name:        "contradictory NOT_FOUND with partner ID",
			requestedID: "por-123",
			raw: resourceownership.OwnershipResult{
				Status: resourceownership.OwnershipStatusNotFound,
				Ownership: resourceownership.ResourceOwnership{
					PartnerID: "P1",
				},
			},
			wantErr: true,
		},
		{
			name:        "zero status unknown",
			requestedID: "por-123",
			raw:         resourceownership.OwnershipResult{},
			wantErr:     true,
		},
		{
			name:        "unrecognized status enum value",
			requestedID: "por-123",
			raw: resourceownership.OwnershipResult{
				Status: resourceownership.OwnershipStatus(99),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resourceownership.ValidateOwnershipResult(tc.requestedID, tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateOwnershipResult() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				if got.Status != tc.raw.Status {
					t.Errorf("got status %v, want %v", got.Status, tc.raw.Status)
				}
				if got.Ownership.ResourceID != tc.raw.Ownership.ResourceID {
					t.Errorf("got resource_id %q, want %q", got.Ownership.ResourceID, tc.raw.Ownership.ResourceID)
				}
				if got.Ownership.PartnerID != tc.raw.Ownership.PartnerID {
					t.Errorf("got partner_id %q, want %q", got.Ownership.PartnerID, tc.raw.Ownership.PartnerID)
				}
			}
		})
	}
}
