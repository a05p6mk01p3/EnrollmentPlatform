package runtime_test

import (
	"strings"
	"testing"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

func TestIdempotencyKeyValidBoundaries(t *testing.T) {
	valid := []string{
		"0123456789abcdef",             // exactly 16
		strings.Repeat("A", 128),       // exactly 128
		"0123456789abcdefghijklmnop",   // 26 printable
		"~!@#$%^&*()_+`-=[]{}|;:,.<>?", // printable ASCII punctuation (30)
	}
	for _, raw := range valid {
		if _, err := runtime.NewIdempotencyKey(raw); err != nil {
			t.Errorf("NewIdempotencyKey(%q) unexpected error: %v", raw, err)
		}
	}
}

func TestIdempotencyKeyInvalidBoundaries(t *testing.T) {
	invalid := []string{
		"",
		"short",                  // too short
		"123456789012345",        // 15 chars
		strings.Repeat("A", 129), // too long
		"01234567 9abcdef",       // contains a space (0x20)
		"0123456789abcdef\n",     // contains control newline (0x0A)
		"\t123456789abcdef",      // contains control tab (0x09)
		"0123456789abcdef\x7f",   // contains DEL (0x7F)
		"0123456789abcdeé",       // non-ASCII UTF-8
		" 0123456789abcdef",      // leading space
		"0123456789abcdef ",      // trailing space
	}
	for _, raw := range invalid {
		if _, err := runtime.NewIdempotencyKey(raw); err == nil {
			t.Errorf("NewIdempotencyKey(%q) expected error, got nil", raw)
		}
	}
}

func TestIdempotencyKeyNoNormalization(t *testing.T) {
	a := mustKey(t, "0123456789abcdef")
	b := mustKey(t, "0123456789abcdeg") // differs by one byte
	if a.Equal(b) {
		t.Fatal("keys differing by one byte must not be equal")
	}
	if a.String() != "0123456789abcdef" {
		t.Fatalf("String() = %q, want exact value", a.String())
	}

	// A leading-space key is invalid, never trimmed into a valid key.
	if _, err := runtime.NewIdempotencyKey(" 0123456789abcdef"); err == nil {
		t.Fatal("leading-space key must be rejected, not trimmed")
	}
}
