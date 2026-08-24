package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

// DefaultDeviceAllocator allocates logical device identifiers with format `dev-<hex>`.
// Logical device identity is generated server-side and never inferred from hardware.
type DefaultDeviceAllocator struct{}

func (DefaultDeviceAllocator) AllocateDeviceID(ctx context.Context, req *domain.PreOnboardingRequest) (string, error) {
	if req != nil && req.DeviceID() != nil && *req.DeviceID() != "" {
		return *req.DeviceID(), nil
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("device allocator: generate random id: %w", err)
	}
	return "dev-" + hex.EncodeToString(b[:]), nil
}

// Validate checks the structural integrity of DefaultDeviceAllocator.
func (DefaultDeviceAllocator) Validate() error { return nil }
