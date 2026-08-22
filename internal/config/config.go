// Package config defines server configuration for the Enrollment API.
//
// Values frozen by the OpenAPI contract (x-protocol-limits) are fixed defaults
// here. OPEN/policy items are explicit placeholders and MUST NOT be silently
// hardcoded (see AGENTS.md §12).
package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds server configuration.
type Config struct {
	// ListenAddr is the HTTP listen address. Deployment-specific; not part of
	// the protocol contract.
	ListenAddr string

	// Protocol limits frozen by the OpenAPI x-protocol-limits section.
	GeneralJSONDefaultBytes  int64 // 262144
	AbsoluteRequestBodyBytes int64 // 4194304
	CSRDecodedBytes          int64 // 65536
	ArrayMaxItems            int   // 128
	StringMaxChars           int   // 4096
	PageSizeDefault          int   // 50
	PageSizeMax              int   // 200

	// OPEN placeholders. 0 means "not configured" until policy/deployment
	// supplies a value.
	TPMEvidenceLimitBytes int64 // OPEN-004A — TPM evidence wire format/limit not frozen.
	ReplayWindowSeconds   int   // CG-003 / protocol §6.4 — replay window not frozen.
}

// Load reads configuration from the environment with contract-derived defaults.
func Load() (Config, error) {
	cfg := Config{
		ListenAddr:               envString("ENROLLMENT_LISTEN_ADDR", ":8080"),
		GeneralJSONDefaultBytes:  262144,
		AbsoluteRequestBodyBytes: 4194304,
		CSRDecodedBytes:          65536,
		ArrayMaxItems:            128,
		StringMaxChars:           4096,
		PageSizeDefault:          50,
		PageSizeMax:              200,
		// OPEN placeholders intentionally left unset.
		TPMEvidenceLimitBytes: 0,
		ReplayWindowSeconds:   0,
	}

	var err error
	if cfg.TPMEvidenceLimitBytes, err = envInt64("ENROLLMENT_TPM_EVIDENCE_LIMIT_BYTES", cfg.TPMEvidenceLimitBytes); err != nil {
		return Config{}, err
	}
	if cfg.ReplayWindowSeconds, err = envInt("ENROLLMENT_REPLAY_WINDOW_SECONDS", cfg.ReplayWindowSeconds); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt64(key string, def int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}
