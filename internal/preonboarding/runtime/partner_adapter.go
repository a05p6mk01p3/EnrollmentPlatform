package runtime

import (
	"context"
	"errors"
	"sync"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
)

// MemoryPartnerAuthorityChecker is an in-memory test double for administrative partner authority.
type MemoryPartnerAuthorityChecker struct {
	mu          sync.RWMutex
	authorities map[string]map[string]bool // principalKey -> partnerID -> bool
}

// Validate checks the structural integrity of MemoryPartnerAuthorityChecker.
func (m *MemoryPartnerAuthorityChecker) Validate() error {
	if m == nil {
		return errors.New("runtime: nil partner authority checker")
	}
	return nil
}

// NewMemoryPartnerAuthorityChecker constructs an empty authority checker.
func NewMemoryPartnerAuthorityChecker() *MemoryPartnerAuthorityChecker {
	return &MemoryPartnerAuthorityChecker{
		authorities: make(map[string]map[string]bool),
	}
}

// GrantPartnerAuthority grants authority for a partner to an admin principal.
func (m *MemoryPartnerAuthorityChecker) GrantPartnerAuthority(admin application.AdminPrincipal, partnerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := admin.Issuer + "#" + admin.Subject
	if _, ok := m.authorities[key]; !ok {
		m.authorities[key] = make(map[string]bool)
	}
	m.authorities[key][partnerID] = true
}

// RevokePartnerAuthority revokes authority for a partner from an admin principal.
func (m *MemoryPartnerAuthorityChecker) RevokePartnerAuthority(admin application.AdminPrincipal, partnerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := admin.Issuer + "#" + admin.Subject
	if _, ok := m.authorities[key]; ok {
		delete(m.authorities[key], partnerID)
	}
}

// HasPartnerAuthority reports whether admin possesses authority for partnerID.
func (m *MemoryPartnerAuthorityChecker) HasPartnerAuthority(ctx context.Context, admin application.AdminPrincipal, partnerID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := admin.Issuer + "#" + admin.Subject
	if pMap, ok := m.authorities[key]; ok {
		return pMap[partnerID], nil
	}
	return false, nil
}

// GetAuthorizedPartners returns all partner IDs for which admin currently holds authority.
func (m *MemoryPartnerAuthorityChecker) GetAuthorizedPartners(ctx context.Context, admin application.AdminPrincipal) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := admin.Issuer + "#" + admin.Subject
	var partners []string
	if pMap, ok := m.authorities[key]; ok {
		for p, ok := range pMap {
			if ok {
				partners = append(partners, p)
			}
		}
	}
	return partners, nil
}

// MemoryPartnerEligibilityChecker is an in-memory test double for partner eligibility.
type MemoryPartnerEligibilityChecker struct {
	mu         sync.RWMutex
	ineligible map[string]bool
}

// Validate checks the structural integrity of MemoryPartnerEligibilityChecker.
func (m *MemoryPartnerEligibilityChecker) Validate() error {
	if m == nil {
		return errors.New("runtime: nil partner eligibility checker")
	}
	return nil
}

// NewMemoryPartnerEligibilityChecker constructs an eligibility checker (all eligible by default).
func NewMemoryPartnerEligibilityChecker() *MemoryPartnerEligibilityChecker {
	return &MemoryPartnerEligibilityChecker{
		ineligible: make(map[string]bool),
	}
}

// SetPartnerIneligible toggles eligibility status for partnerID.
func (m *MemoryPartnerEligibilityChecker) SetPartnerIneligible(partnerID string, ineligible bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ineligible {
		m.ineligible[partnerID] = true
	} else {
		delete(m.ineligible, partnerID)
	}
}

// IsPartnerEligible reports whether partnerID is currently eligible.
func (m *MemoryPartnerEligibilityChecker) IsPartnerEligible(ctx context.Context, partnerID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return !m.ineligible[partnerID], nil
}
