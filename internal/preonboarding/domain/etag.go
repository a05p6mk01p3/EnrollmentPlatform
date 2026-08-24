package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// canonicalETagPayload is the private, deterministic data structure hashed to
// produce the strong, opaque HTTP entity tag.
//
// Invariant: it captures the full effective representation (including
// effective status derived from clock). Crossing expires_at changes the
// effective status, producing a different strong ETag even when the persisted
// resource_version has not incremented.
type canonicalETagPayload struct {
	ID                   string  `json:"id"`
	PartnerID            string  `json:"partner_id"`
	EffectiveStatus      string  `json:"effective_status"`
	ResourceVersion      int     `json:"resource_version"`
	DeviceID             *string `json:"device_id,omitempty"`
	CreatedAtRFC3339     string  `json:"created_at"`
	ExpiresAtRFC3339     string  `json:"expires_at"`
	Hostname             string  `json:"hostname"`
	SerialNumber         string  `json:"serial_number"`
	SMBIOSUUID           string  `json:"smbios_uuid"`
	Manufacturer         string  `json:"manufacturer"`
	Model                string  `json:"model"`
	TPMPresent           bool    `json:"tpm_present"`
	TPMVendor            string  `json:"tpm_vendor"`
	EKPublicHash         string  `json:"ek_public_hash"`
	HardwareBacked       *bool   `json:"hardware_backed,omitempty"`
	PrivateKeyExportable *bool   `json:"private_key_exportable,omitempty"`
	Provider             *string `json:"provider,omitempty"`
	TPMReady             *bool   `json:"tpm_ready,omitempty"`
	AgentPlatform        string  `json:"agent_platform"`
	AgentVersion         string  `json:"agent_version"`
}

// ComputeETag generates an opaque, strong entity tag for the effective
// representation of the request at time `now`.
//
// The returned string is double-quoted according to RFC 9110 strong ETag
// representation (e.g. `"0123456789abcdef..."`).
func ComputeETag(req *PreOnboardingRequest, now time.Time) string {
	if req == nil {
		return ""
	}
	claimed := req.ClaimedDevice()
	agent := req.Agent()

	payload := canonicalETagPayload{
		ID:                   string(req.ID()),
		PartnerID:            string(req.PartnerID()),
		EffectiveStatus:      string(req.EffectiveStatus(now)),
		ResourceVersion:      req.ResourceVersion(),
		DeviceID:             req.DeviceID(),
		CreatedAtRFC3339:     req.CreatedAt().UTC().Format(time.RFC3339Nano),
		ExpiresAtRFC3339:     req.ExpiresAt().UTC().Format(time.RFC3339Nano),
		Hostname:             claimed.Hostname,
		SerialNumber:         claimed.SerialNumber,
		SMBIOSUUID:           claimed.SMBIOSUUID,
		Manufacturer:         claimed.Manufacturer,
		Model:                claimed.Model,
		TPMPresent:           claimed.TPMPresent,
		TPMVendor:            claimed.TPMVendor,
		EKPublicHash:         claimed.EKPublicHash,
		HardwareBacked:       claimed.HardwareBacked,
		PrivateKeyExportable: claimed.PrivateKeyExportable,
		Provider:             claimed.Provider,
		TPMReady:             claimed.TPMReady,
		AgentPlatform:        agent.Platform,
		AgentVersion:         agent.Version,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		// Should not happen with well-typed primitives
		b = []byte(fmt.Sprintf("%s:%s:%s:%d", req.ID(), req.PartnerID(), req.EffectiveStatus(now), req.ResourceVersion()))
	}

	digest := sha256.Sum256(b)
	return `"` + hex.EncodeToString(digest[:]) + `"`
}

// NormalizeETag strips enclosing quotes or whitespace for comparison.
func NormalizeETag(raw string) string {
	trimmed := strings.TrimSpace(raw)
	return strings.Trim(trimmed, `"`)
}

// MatchETag evaluates whether the client-supplied If-Match matches the current
// strong ETag. Weak ETags (W/) and wildcard (*) are rejected by the contract.
func MatchETag(ifMatch string, currentETag string) bool {
	if strings.HasPrefix(strings.TrimSpace(ifMatch), "W/") || strings.TrimSpace(ifMatch) == "*" {
		return false
	}
	normIfMatch := NormalizeETag(ifMatch)
	normCurrent := NormalizeETag(currentETag)
	if normIfMatch == "" || normCurrent == "" {
		return false
	}
	return normIfMatch == normCurrent
}
