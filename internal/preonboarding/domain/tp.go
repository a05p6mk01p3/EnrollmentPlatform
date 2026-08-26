package domain

import (
	"time"
)

type TPStatus string

const (
	TPStatusActive   TPStatus = "ACTIVE"
	TPStatusDisabled TPStatus = "DISABLED"
)

type TemporaryPrincipal struct {
	TemporaryPrincipalID string
	PartnerID            PartnerID
	Status               TPStatus
	ExpiresAt            time.Time
	MaxSubmissions       int
	CommittedSubmissions int
}

func (tp *TemporaryPrincipal) IsActive(now time.Time) bool {
	if tp == nil {
		return false
	}
	if tp.Status != TPStatusActive {
		return false
	}
	if now.After(tp.ExpiresAt) || now.Equal(tp.ExpiresAt) {
		return false
	}
	return true
}

func (tp *TemporaryPrincipal) HasQuotaRemaining() bool {
	if tp == nil {
		return false
	}
	return tp.CommittedSubmissions < tp.MaxSubmissions
}
