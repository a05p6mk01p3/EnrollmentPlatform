package domain_test

import (
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

func TestNewRequest(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)

	req, err := domain.NewRequest(
		"por-123",
		"P1",
		domain.ClaimedDevice{Hostname: "node-1", SerialNumber: "sn-1", SMBIOSUUID: "uuid-1", Manufacturer: "Acme", Model: "M1", TPMPresent: true},
		domain.Agent{Platform: "windows", Version: "1.0.0"},
		now,
		expires,
	)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	if req.ID() != "por-123" {
		t.Errorf("ID = %v, want por-123", req.ID())
	}
	if req.PartnerID() != "P1" {
		t.Errorf("PartnerID = %v, want P1", req.PartnerID())
	}
	if req.Status() != domain.StatePendingApproval {
		t.Errorf("Status = %v, want PENDING_APPROVAL", req.Status())
	}
	if req.ResourceVersion() != 1 {
		t.Errorf("ResourceVersion = %d, want 1", req.ResourceVersion())
	}
	if req.DeviceID() != nil {
		t.Errorf("DeviceID = %v, want nil", req.DeviceID())
	}
	if req.IsTerminal() {
		t.Errorf("IsTerminal = true, want false")
	}
}

func TestNewRequestValidation(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)
	claimed := domain.ClaimedDevice{Hostname: "node-1"}
	agent := domain.Agent{Platform: "linux", Version: "1.0"}

	if _, err := domain.NewRequest("", "P1", claimed, agent, now, expires); err == nil {
		t.Error("expected error on empty ID")
	}
	if _, err := domain.NewRequest("por-1", "", claimed, agent, now, expires); err == nil {
		t.Error("expected error on empty partner ID")
	}
	if _, err := domain.NewRequest("por-1", "P1", claimed, agent, expires, now); err == nil {
		t.Error("expected error when expires_at <= created_at")
	}
}

func TestRestoreRequest(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)
	devID := "dev-abc"

	req, err := domain.RestoreRequest(
		"por-123",
		"P1",
		domain.ClaimedDevice{Hostname: "node-1"},
		domain.Agent{Platform: "windows", Version: "1.0.0"},
		domain.StateEnrollmentReady,
		&devID,
		now,
		expires,
		3,
	)
	if err != nil {
		t.Fatalf("RestoreRequest failed: %v", err)
	}
	if req.Status() != domain.StateEnrollmentReady {
		t.Errorf("Status = %v, want ENROLLMENT_READY", req.Status())
	}
	if req.DeviceID() == nil || *req.DeviceID() != "dev-abc" {
		t.Errorf("DeviceID = %v, want dev-abc", req.DeviceID())
	}
	if req.ResourceVersion() != 3 {
		t.Errorf("ResourceVersion = %d, want 3", req.ResourceVersion())
	}

	// Restore INVALIDATED
	reqInv, err := domain.RestoreRequest(
		"por-inv",
		"P1",
		domain.ClaimedDevice{},
		domain.Agent{},
		domain.StateInvalidated,
		nil,
		now,
		expires,
		2,
	)
	if err != nil {
		t.Fatalf("RestoreRequest for INVALIDATED failed: %v", err)
	}
	if reqInv.Status() != domain.StateInvalidated {
		t.Errorf("Status = %v, want INVALIDATED", reqInv.Status())
	}

	// Restore invalid state
	if _, err := domain.RestoreRequest("por-1", "P1", domain.ClaimedDevice{}, domain.Agent{}, "NON_EXISTENT_STATE", nil, now, expires, 1); err == nil {
		t.Error("expected error on invalid state restore")
	}
	// Restore invalid version
	if _, err := domain.RestoreRequest("por-1", "P1", domain.ClaimedDevice{}, domain.Agent{}, domain.StatePendingApproval, nil, now, expires, 0); err == nil {
		t.Error("expected error on resource_version < 1")
	}
}

func TestApproveLifecycle(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)
	req, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{}, domain.Agent{}, now, expires)

	// Successful approve allocates device ID and increments resource version
	if err := req.Approve(now.Add(time.Minute), "dev-999"); err != nil {
		t.Fatalf("Approve failed: %v", err)
	}
	if req.Status() != domain.StateEnrollmentReady {
		t.Errorf("Status = %v, want ENROLLMENT_READY", req.Status())
	}
	if req.DeviceID() == nil || *req.DeviceID() != "dev-999" {
		t.Errorf("DeviceID = %v, want dev-999", req.DeviceID())
	}
	if req.ResourceVersion() != 2 {
		t.Errorf("ResourceVersion = %d, want 2", req.ResourceVersion())
	}

	// Repeated approve fails with state conflict
	if err := req.Approve(now.Add(2*time.Minute), "dev-999"); err == nil {
		t.Error("expected conflict error on repeated approve")
	}

	// Reject after approve fails with state conflict
	if err := req.Reject(now.Add(3*time.Minute), "reason"); err == nil {
		t.Error("expected conflict error on reject after approve")
	}
}

func TestApprovePreservesExistingDeviceID(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)
	existingDev := "dev-existing"
	req, _ := domain.RestoreRequest("por-1", "P1", domain.ClaimedDevice{}, domain.Agent{}, domain.StatePendingApproval, &existingDev, now, expires, 1)

	if err := req.Approve(now.Add(time.Minute), "dev-new-should-be-ignored"); err != nil {
		t.Fatalf("Approve failed: %v", err)
	}
	if req.DeviceID() == nil || *req.DeviceID() != "dev-existing" {
		t.Errorf("DeviceID = %v, want preserved dev-existing", req.DeviceID())
	}
}

func TestRejectLifecycle(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)
	req, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{}, domain.Agent{}, now, expires)

	if err := req.Reject(now.Add(time.Minute), "suspicious hardware"); err != nil {
		t.Fatalf("Reject failed: %v", err)
	}
	if req.Status() != domain.StateRejected {
		t.Errorf("Status = %v, want REJECTED", req.Status())
	}
	if req.DeviceID() != nil {
		t.Errorf("DeviceID = %v, rejection must NEVER set device ID", req.DeviceID())
	}
	if req.ResourceVersion() != 2 {
		t.Errorf("ResourceVersion = %d, want 2", req.ResourceVersion())
	}
	if !req.IsTerminal() {
		t.Errorf("IsTerminal = false, want true for REJECTED")
	}

	// Repeated reject fails with state conflict
	if err := req.Reject(now.Add(2*time.Minute), "second reject"); err == nil {
		t.Error("expected conflict error on repeated reject")
	}

	// Approve after reject fails with state conflict
	if err := req.Approve(now.Add(3*time.Minute), "dev-123"); err == nil {
		t.Error("expected conflict error on approve after reject")
	}
}

func TestEffectiveExpiry(t *testing.T) {
	now := time.Now()
	expires := now.Add(10 * time.Minute)
	req, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{}, domain.Agent{}, now, expires)

	// Before expiry
	if eff := req.EffectiveStatus(now.Add(5 * time.Minute)); eff != domain.StatePendingApproval {
		t.Errorf("EffectiveStatus at 5m = %v, want PENDING_APPROVAL", eff)
	}

	// Exactly at expires_at
	if eff := req.EffectiveStatus(expires); eff != domain.StateExpired {
		t.Errorf("EffectiveStatus at expires = %v, want EXPIRED", eff)
	}

	// After expires_at
	if eff := req.EffectiveStatus(now.Add(15 * time.Minute)); eff != domain.StateExpired {
		t.Errorf("EffectiveStatus after expires = %v, want EXPIRED", eff)
	}

	// Stored status remains PENDING_APPROVAL (logical expiry without forced mutation)
	if req.Status() != domain.StatePendingApproval {
		t.Errorf("stored Status = %v, want PENDING_APPROVAL", req.Status())
	}

	// Approve attempt post-expiry fails with ErrExpired
	if err := req.Approve(now.Add(15*time.Minute), "dev-1"); err != domain.ErrExpired {
		t.Errorf("Approve post-expiry error = %v, want ErrExpired", err)
	}

	// Reject attempt post-expiry fails with ErrExpired
	if err := req.Reject(now.Add(15*time.Minute), "late reject"); err != domain.ErrExpired {
		t.Errorf("Reject post-expiry error = %v, want ErrExpired", err)
	}

	// Terminal REJECTED is not altered by clock
	reqRejected, _ := domain.NewRequest("por-2", "P1", domain.ClaimedDevice{}, domain.Agent{}, now, expires)
	_ = reqRejected.Reject(now.Add(time.Minute), "denied")
	if eff := reqRejected.EffectiveStatus(now.Add(20 * time.Minute)); eff != domain.StateRejected {
		t.Errorf("REJECTED EffectiveStatus post-expiry = %v, want REJECTED", eff)
	}
}
