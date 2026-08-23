package partnerauth

import (
	"testing"
	"time"
)

func nowPlusHours(t *testing.T, h int) time.Time {
	t.Helper()
	return time.Now().Add(time.Duration(h) * time.Hour)
}

func activeTP(id, partner string, scopes []string, expiresAt time.Time) TemporaryPrincipalAuthorization {
	return TemporaryPrincipalAuthorization{
		TemporaryPrincipalID: id,
		PartnerID:            partner,
		Scopes:               scopes,
		Status:               TemporaryPrincipalStatusActive,
		ExpiresAt:            &expiresAt,
	}
}
