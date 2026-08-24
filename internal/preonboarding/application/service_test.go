package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
)

type testHarness struct {
	store       *runtime.MemoryStore
	recorder    *runtime.MemoryAuditRecorder
	clock       *runtime.MockClock
	allocator   *runtime.DefaultDeviceAllocator
	partnerAuth *runtime.MemoryPartnerAuthorityChecker
	partnerElig *runtime.MemoryPartnerEligibilityChecker
	service     *application.Service
}

func newTestHarness(t *testing.T, initialTime time.Time) *testHarness {
	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	clock := runtime.NewMockClock(initialTime)
	allocator := &runtime.DefaultDeviceAllocator{}
	partnerAuth := runtime.NewMemoryPartnerAuthorityChecker()
	partnerElig := runtime.NewMemoryPartnerEligibilityChecker()

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	return &testHarness{
		store:       store,
		recorder:    recorder,
		clock:       clock,
		allocator:   allocator,
		partnerAuth: partnerAuth,
		partnerElig: partnerElig,
		service:     svc,
	}
}

func TestProductionCreateFailsClosed(t *testing.T) {
	h := newTestHarness(t, time.Now())
	ctx := context.Background()

	_, err := h.service.CreatePreOnboardingRequest(ctx, application.CreateCommand{
		PartnerID:     "P1",
		ClaimedDevice: domain.ClaimedDevice{Hostname: "host-1"},
		Agent:         domain.Agent{Platform: "windows", Version: "1.0"},
	})
	if err != application.ErrDependencyUnavailable {
		t.Fatalf("CreatePreOnboardingRequest error = %v, want ErrDependencyUnavailable", err)
	}

	// Verify zero side effects
	if h.store.CountRequests() != 0 {
		t.Errorf("stored requests = %d, want 0", h.store.CountRequests())
	}
	if h.recorder.Count() != 0 {
		t.Errorf("audit events = %d, want 0", h.recorder.Count())
	}
}

func TestGetPublic(t *testing.T) {
	now := time.Now()
	h := newTestHarness(t, now)
	ctx := context.Background()

	req, _ := domain.NewRequest("por-pub-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	h.store.SeedRequest(req)
	expectedETag := domain.ComputeETag(req, now)

	// Valid read before expiry
	res, err := h.service.GetPublic(ctx, "por-pub-1")
	if err != nil {
		t.Fatalf("GetPublic error = %v", err)
	}
	if res.ETag != expectedETag {
		t.Errorf("ETag = %s, want %s", res.ETag, expectedETag)
	}
	if res.EffectiveStatus != domain.StatePendingApproval {
		t.Errorf("EffectiveStatus = %s, want %s", res.EffectiveStatus, domain.StatePendingApproval)
	}

	// Advance clock past expiration => ErrResourceExpired
	h.clock.Advance(15 * time.Minute)
	_, err = h.service.GetPublic(ctx, "por-pub-1")
	if err != application.ErrResourceExpired {
		t.Fatalf("GetPublic expired error = %v, want ErrResourceExpired", err)
	}

	// Nonexistent request => ErrNotFound
	_, err = h.service.GetPublic(ctx, "por-nonexistent")
	if err != application.ErrNotFound {
		t.Fatalf("GetPublic nonexistent error = %v, want ErrNotFound", err)
	}
}

func TestGetAdmin_ConcealmentAndExpiry(t *testing.T) {
	now := time.Now()
	h := newTestHarness(t, now)
	ctx := context.Background()

	admin := application.AdminPrincipal{Issuer: "https://auth.example.com", Subject: "admin-1"}
	h.partnerAuth.GrantPartnerAuthority(admin, "P1")

	req1, _ := domain.NewRequest("por-admin-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	req2, _ := domain.NewRequest("por-admin-2", "P2", domain.ClaimedDevice{Hostname: "h2"}, domain.Agent{}, now, now.Add(10*time.Minute))
	h.store.SeedRequest(req1)
	h.store.SeedRequest(req2)

	// 1. Authorized partner => 200 equivalent
	res, err := h.service.GetAdmin(ctx, admin, "por-admin-1")
	if err != nil {
		t.Fatalf("GetAdmin authorized error = %v", err)
	}
	if res.Request.ID() != "por-admin-1" {
		t.Errorf("Request ID = %s, want por-admin-1", res.Request.ID())
	}

	// 2. Unauthorized partner => ErrNotFound concealment (M5.5-DEC-002)
	_, err = h.service.GetAdmin(ctx, admin, "por-admin-2")
	if err != application.ErrNotFound {
		t.Fatalf("GetAdmin unauthorized error = %v, want ErrNotFound (concealment)", err)
	}

	// 3. Expired request for authorized partner => returns EffectiveStatus EXPIRED (never 410!)
	h.clock.Advance(15 * time.Minute)
	resExp, err := h.service.GetAdmin(ctx, admin, "por-admin-1")
	if err != nil {
		t.Fatalf("GetAdmin expired error = %v", err)
	}
	if resExp.EffectiveStatus != domain.StateExpired {
		t.Errorf("EffectiveStatus = %s, want EXPIRED", resExp.EffectiveStatus)
	}
}

func TestListAdmin_FilterAuthorizedPartners(t *testing.T) {
	now := time.Now()
	h := newTestHarness(t, now)
	ctx := context.Background()

	admin := application.AdminPrincipal{Issuer: "https://auth.example.com", Subject: "admin-1"}
	h.partnerAuth.GrantPartnerAuthority(admin, "P1")
	h.partnerAuth.GrantPartnerAuthority(admin, "P2")

	req1, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	req2, _ := domain.NewRequest("por-2", "P2", domain.ClaimedDevice{Hostname: "h2"}, domain.Agent{}, now, now.Add(10*time.Minute))
	req3, _ := domain.NewRequest("por-3", "P3", domain.ClaimedDevice{Hostname: "h3"}, domain.Agent{}, now, now.Add(10*time.Minute))
	h.store.SeedRequest(req1)
	h.store.SeedRequest(req2)
	h.store.SeedRequest(req3)

	// List all authorized partners (P1, P2) -> P3 omitted
	res, err := h.service.ListAdmin(ctx, admin, application.AdminListFilter{})
	if err != nil {
		t.Fatalf("ListAdmin error = %v", err)
	}
	if len(res.Items) != 2 {
		t.Fatalf("ListAdmin items = %d, want 2", len(res.Items))
	}

	// Filter by authorized partner P1
	p1 := "P1"
	resP1, err := h.service.ListAdmin(ctx, admin, application.AdminListFilter{PartnerID: &p1})
	if err != nil {
		t.Fatalf("ListAdmin P1 error = %v", err)
	}
	if len(resP1.Items) != 1 || resP1.Items[0].Request.ID() != "por-1" {
		t.Fatalf("ListAdmin P1 items = %d, want 1 (por-1)", len(resP1.Items))
	}

	// Filter by unauthorized partner P3 -> empty list
	p3 := "P3"
	resP3, err := h.service.ListAdmin(ctx, admin, application.AdminListFilter{PartnerID: &p3})
	if err != nil {
		t.Fatalf("ListAdmin P3 error = %v", err)
	}
	if len(resP3.Items) != 0 {
		t.Fatalf("ListAdmin P3 items = %d, want 0", len(resP3.Items))
	}
}

func TestApprove_IdempotencyAndReplay(t *testing.T) {
	now := time.Now()
	h := newTestHarness(t, now)
	ctx := context.Background()

	admin := application.AdminPrincipal{Issuer: "https://auth.example.com", Subject: "admin-1"}
	h.partnerAuth.GrantPartnerAuthority(admin, "P1")

	req, _ := domain.NewRequest("por-app-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	h.store.SeedRequest(req)
	preETag := domain.ComputeETag(req, now)

	cmd := application.ApproveCommand{
		ID:             "por-app-1",
		IfMatch:        preETag,
		IdempotencyKey: "idem-key-app-12345",
		ExpectedStatus: "PENDING_APPROVAL",
		Reason:         "hardware validated",
		CorrelationID:  "corr-1",
	}

	// 1. Initial NEW approve
	res1, err := h.service.Approve(ctx, admin, cmd)
	if err != nil {
		t.Fatalf("Approve NEW error = %v", err)
	}
	if res1.IsReplay {
		t.Fatal("res1.IsReplay = true, want false")
	}
	if res1.Status != domain.StateEnrollmentReady {
		t.Errorf("Status = %s, want ENROLLMENT_READY", res1.Status)
	}
	if res1.DeviceID == "" {
		t.Error("DeviceID must not be empty on approval")
	}
	if res1.ResourceVersion != 2 {
		t.Errorf("ResourceVersion = %d, want 2", res1.ResourceVersion)
	}

	// Verify PREONBOARD_APPROVED audit event
	if h.recorder.CountByType(application.AuditEventApproved) != 1 {
		t.Errorf("AuditEventApproved count = %d, want 1", h.recorder.CountByType(application.AuditEventApproved))
	}

	// 2. Exact REPLAY with same key & fingerprint
	res2, err := h.service.Approve(ctx, admin, cmd)
	if err != nil {
		t.Fatalf("Approve REPLAY error = %v", err)
	}
	if !res2.IsReplay {
		t.Fatal("res2.IsReplay = false, want true")
	}
	if res2.DeviceID != res1.DeviceID {
		t.Errorf("replay DeviceID = %s, want %s", res2.DeviceID, res1.DeviceID)
	}
	if res2.ETag != res1.ETag {
		t.Errorf("replay ETag = %s, want %s", res2.ETag, res1.ETag)
	}
	// Replay must NOT emit duplicate audit events
	if h.recorder.CountByType(application.AuditEventApproved) != 1 {
		t.Errorf("AuditEventApproved count after replay = %d, want 1", h.recorder.CountByType(application.AuditEventApproved))
	}

	// 3. Replay after partner becomes ineligible STILL succeeds (does not re-run eligibility)
	h.partnerElig.SetPartnerIneligible("P1", true)
	res3, err := h.service.Approve(ctx, admin, cmd)
	if err != nil {
		t.Fatalf("Approve REPLAY after ineligibility error = %v", err)
	}
	if !res3.IsReplay {
		t.Fatal("res3.IsReplay = false, want true")
	}

	// 4. Replay after admin loses partner authority MUST fail closed
	h.partnerAuth.RevokePartnerAuthority(admin, "P1")
	_, err = h.service.Approve(ctx, admin, cmd)
	if err != application.ErrPartnerNotAuthorized {
		t.Fatalf("Approve REPLAY without partner authority error = %v, want ErrPartnerNotAuthorized", err)
	}
}

// Spy allocator to prove M55-SOL-009: allocator is never called when device_id already exists.
type spyAllocator struct {
	calls int
}

func (s *spyAllocator) AllocateDeviceID(ctx context.Context, req *domain.PreOnboardingRequest) (string, error) {
	s.calls++
	return "dev-allocated-from-spy", nil
}

func TestApprove_PreservesExistingDeviceID_NeverCallsAllocator(t *testing.T) {
	now := time.Now()
	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	clock := runtime.NewMockClock(now)
	spy := &spyAllocator{}
	partnerAuth := runtime.NewMemoryPartnerAuthorityChecker()
	partnerElig := runtime.NewMemoryPartnerEligibilityChecker()

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    spy,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	admin := application.AdminPrincipal{Issuer: "https://auth.example.com", Subject: "admin-1"}
	partnerAuth.GrantPartnerAuthority(admin, "P1")

	existingDev := "dev-pre-existing-123"
	req, _ := domain.RestoreRequest("por-pres-dev", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, domain.StatePendingApproval, &existingDev, now, now.Add(time.Hour), 1)
	store.SeedRequest(req)
	etag := domain.ComputeETag(req, now)

	cmd := application.ApproveCommand{
		ID:             "por-pres-dev",
		IfMatch:        etag,
		IdempotencyKey: "idem-key-preserve-dev-12345",
		ExpectedStatus: "PENDING_APPROVAL",
		Reason:         "approved",
		CorrelationID:  "corr-pres",
	}

	res, err := svc.Approve(context.Background(), admin, cmd)
	if err != nil {
		t.Fatalf("Approve error = %v", err)
	}
	if res.DeviceID != existingDev {
		t.Errorf("DeviceID = %s, want preserved %s", res.DeviceID, existingDev)
	}
	if spy.calls != 0 {
		t.Errorf("spyAllocator.calls = %d, want 0 (must not allocate when device_id already exists)", spy.calls)
	}
}

func TestReject_PreservesExistingDeviceID_OnNewAndReplay(t *testing.T) {
	now := time.Now()
	h := newTestHarness(t, now)
	ctx := context.Background()

	admin := application.AdminPrincipal{Issuer: "https://auth.example.com", Subject: "admin-1"}
	h.partnerAuth.GrantPartnerAuthority(admin, "P1")

	existingDev := "dev-pre-existing-rej"
	req, _ := domain.RestoreRequest("por-rej-dev", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, domain.StatePendingApproval, &existingDev, now, now.Add(time.Hour), 1)
	h.store.SeedRequest(req)
	etag := domain.ComputeETag(req, now)

	cmd := application.RejectCommand{
		ID:             "por-rej-dev",
		IfMatch:        etag,
		IdempotencyKey: "idem-key-rej-preserve-12345",
		ExpectedStatus: "PENDING_APPROVAL",
		Reason:         "hardware validation failed",
		CorrelationID:  "corr-rej-1",
	}

	// 1. Initial NEW reject
	res1, err := h.service.Reject(ctx, admin, cmd)
	if err != nil {
		t.Fatalf("Reject error = %v", err)
	}
	if res1.Request.DeviceID() == nil || *res1.Request.DeviceID() != existingDev {
		t.Errorf("NEW reject DeviceID = %v, want preserved %s", res1.Request.DeviceID(), existingDev)
	}

	// 2. Exact REPLAY
	res2, err := h.service.Reject(ctx, admin, cmd)
	if err != nil {
		t.Fatalf("Reject replay error = %v", err)
	}
	if !res2.IsReplay {
		t.Fatal("res2.IsReplay = false, want true")
	}
	if res2.Request.DeviceID() == nil || *res2.Request.DeviceID() != existingDev {
		t.Errorf("REPLAY reject DeviceID = %v, want preserved %s", res2.Request.DeviceID(), existingDev)
	}
	if res2.ETag != res1.ETag {
		t.Errorf("REPLAY ETag = %s, want %s", res2.ETag, res1.ETag)
	}
}

type brokenUOWManager struct{}

func (brokenUOWManager) Begin(ctx context.Context) (application.UnitOfWork, error) { return nil, nil }
func (brokenUOWManager) Validate() error                                           { return errors.New("broken uow manager") }

type brokenAuthorityChecker struct{}

func (brokenAuthorityChecker) HasPartnerAuthority(ctx context.Context, admin application.AdminPrincipal, partnerID string) (bool, error) {
	return false, nil
}
func (brokenAuthorityChecker) GetAuthorizedPartners(ctx context.Context, admin application.AdminPrincipal) ([]string, error) {
	return nil, nil
}
func (brokenAuthorityChecker) Validate() error { return errors.New("broken authority checker") }

type brokenEligibilityChecker struct{}

func (brokenEligibilityChecker) IsPartnerEligible(ctx context.Context, partnerID string) (bool, error) {
	return false, nil
}
func (brokenEligibilityChecker) Validate() error { return errors.New("broken eligibility checker") }

type brokenAllocator struct{}

func (brokenAllocator) AllocateDeviceID(ctx context.Context, req *domain.PreOnboardingRequest) (string, error) {
	return "", nil
}
func (brokenAllocator) Validate() error { return errors.New("broken allocator") }

type brokenClock struct{}

func (brokenClock) Now() time.Time  { return time.Now() }
func (brokenClock) Validate() error { return errors.New("broken clock") }

type brokenPolicy struct{}

func (brokenPolicy) ReservationDuration() time.Duration { return time.Hour }
func (brokenPolicy) Validate() error                    { return errors.New("broken policy") }

func TestStructuralValidation_RejectsInvalidDependencies(t *testing.T) {
	now := time.Now()
	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	clock := runtime.NewMockClock(now)
	allocator := &runtime.DefaultDeviceAllocator{}
	partnerAuth := runtime.NewMemoryPartnerAuthorityChecker()
	partnerElig := runtime.NewMemoryPartnerEligibilityChecker()
	retention := application.StaticIdempotencyRetentionPolicy{Duration: time.Hour}

	// Missing / nil UOWManager
	if _, err := application.NewService(application.ServiceConfig{
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for missing UOWManager")
	}

	// Broken UOWManager whose Validate() returns error
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         brokenUOWManager{},
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for broken UOWManager")
	}

	// Broken PartnerAuth whose Validate() returns error
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        brokenAuthorityChecker{},
		PartnerEligibility: partnerElig,
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for broken PartnerAuth")
	}

	// Broken PartnerEligibility whose Validate() returns error
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: brokenEligibilityChecker{},
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for broken PartnerEligibility")
	}

	// Broken DeviceAllocator whose Validate() returns error
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    brokenAllocator{},
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for broken DeviceAllocator")
	}

	// Broken Clock whose Validate() returns error
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              brokenClock{},
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for broken Clock")
	}

	// Broken RetentionPolicy whose Validate() returns error
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    brokenPolicy{},
	}); err == nil {
		t.Error("expected error for broken RetentionPolicy")
	}

	// Typed-nil dependencies
	var typedNilStore *runtime.MemoryStore = nil
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         typedNilStore,
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for typed-nil UOWManager")
	}

	var typedNilClock *runtime.MockClock = nil
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              typedNilClock,
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for typed-nil Clock")
	}

	var typedNilAuth *runtime.MemoryPartnerAuthorityChecker = nil
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        typedNilAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for typed-nil PartnerAuth")
	}

	var typedNilElig *runtime.MemoryPartnerEligibilityChecker = nil
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: typedNilElig,
		RetentionPolicy:    retention,
	}); err == nil {
		t.Error("expected error for typed-nil PartnerEligibility")
	}

	// Missing or non-positive RetentionPolicy
	if _, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    allocator,
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: 0},
	}); err == nil {
		t.Error("expected error for non-positive RetentionPolicy")
	}

	// UnavailableService passes Validate
	unavail := application.NewUnavailableService()
	if err := unavail.Validate(); err != nil {
		t.Errorf("NewUnavailableService Validate failed: %v", err)
	}
}

func TestRawResourceVersionRejectedAsIfMatch(t *testing.T) {
	now := time.Now()
	h := newTestHarness(t, now)
	ctx := context.Background()
	admin := application.AdminPrincipal{Issuer: "https://auth.example.com", Subject: "admin-1"}
	h.partnerAuth.GrantPartnerAuthority(admin, "P1")

	req, _ := domain.RestoreRequest(
		"por-v7", "P1",
		domain.ClaimedDevice{Hostname: "h7"},
		domain.Agent{Platform: "windows", Version: "1.0"},
		domain.StatePendingApproval, nil, now, now.Add(time.Hour), 7,
	)
	h.store.SeedRequest(req)
	strongETag := domain.ComputeETag(req, now)

	// Approve with raw resource_version "7" => ErrPreconditionFailed (HTTP 412)
	_, err := h.service.Approve(ctx, admin, application.ApproveCommand{
		ID:             "por-v7",
		IfMatch:        `"7"`,
		IdempotencyKey: "idem-key-v7-app-001",
		ExpectedStatus: "PENDING_APPROVAL",
		Reason:         "attempt approve raw version",
	})
	if !errors.Is(err, application.ErrPreconditionFailed) {
		t.Fatalf("Approve with If-Match: \"7\" error = %v, want ErrPreconditionFailed", err)
	}

	// Reject with raw resource_version "7" => ErrPreconditionFailed (HTTP 412)
	_, err = h.service.Reject(ctx, admin, application.RejectCommand{
		ID:             "por-v7",
		IfMatch:        `"7"`,
		IdempotencyKey: "idem-key-v7-rej-001",
		ExpectedStatus: "PENDING_APPROVAL",
		Reason:         "attempt reject raw version",
	})
	if !errors.Is(err, application.ErrPreconditionFailed) {
		t.Fatalf("Reject with If-Match: \"7\" error = %v, want ErrPreconditionFailed", err)
	}

	// Approve with actual strong ETag => succeeds
	res, err := h.service.Approve(ctx, admin, application.ApproveCommand{
		ID:             "por-v7",
		IfMatch:        strongETag,
		IdempotencyKey: "idem-key-v7-app-002",
		ExpectedStatus: "PENDING_APPROVAL",
		Reason:         "valid strong etag approve",
	})
	if err != nil {
		t.Fatalf("Approve with strong ETag error = %v, want nil", err)
	}
	if res.Status != domain.StateEnrollmentReady {
		t.Fatalf("res.Status = %v, want ENROLLMENT_READY", res.Status)
	}
}

func TestExpiryBoundaryIfMatch(t *testing.T) {
	now := time.Now()
	h := newTestHarness(t, now)
	ctx := context.Background()
	admin := application.AdminPrincipal{Issuer: "https://auth.example.com", Subject: "admin-1"}
	h.partnerAuth.GrantPartnerAuthority(admin, "P1")

	req, _ := domain.RestoreRequest(
		"por-exp-boundary", "P1",
		domain.ClaimedDevice{Hostname: "hexp"},
		domain.Agent{Platform: "windows", Version: "1.0"},
		domain.StatePendingApproval, nil, now, now.Add(10*time.Minute), 3,
	)
	h.store.SeedRequest(req)
	preExpiryETag := domain.ComputeETag(req, now)

	// Advance time past expiration
	h.clock.Advance(15 * time.Minute)
	afterExpiryTime := h.clock.Now()
	expiredETag := domain.ComputeETag(req, afterExpiryTime)

	// 1. Raw resource_version "3" after expiry => ErrPreconditionFailed (412)
	_, err := h.service.Approve(ctx, admin, application.ApproveCommand{
		ID:             "por-exp-boundary",
		IfMatch:        `"3"`,
		IdempotencyKey: "idem-key-exp-000001",
		ExpectedStatus: "PENDING_APPROVAL",
	})
	if !errors.Is(err, application.ErrPreconditionFailed) {
		t.Fatalf("Approve raw version after expiry error = %v, want ErrPreconditionFailed (412)", err)
	}

	// 2. Pre-expiry ETag after expiry => ErrPreconditionFailed (412)
	_, err = h.service.Approve(ctx, admin, application.ApproveCommand{
		ID:             "por-exp-boundary",
		IfMatch:        preExpiryETag,
		IdempotencyKey: "idem-key-exp-000002",
		ExpectedStatus: "PENDING_APPROVAL",
	})
	if !errors.Is(err, application.ErrPreconditionFailed) {
		t.Fatalf("Approve pre-expiry ETag after expiry error = %v, want ErrPreconditionFailed (412)", err)
	}

	// 3. New effective strong ETag (post-expiry) => ErrStateConflict (409)
	_, err = h.service.Approve(ctx, admin, application.ApproveCommand{
		ID:             "por-exp-boundary",
		IfMatch:        expiredETag,
		IdempotencyKey: "idem-key-exp-000003",
		ExpectedStatus: "PENDING_APPROVAL",
	})
	if !errors.Is(err, application.ErrStateConflict) {
		t.Fatalf("Approve matching expired strong ETag error = %v, want ErrStateConflict (409)", err)
	}
}
