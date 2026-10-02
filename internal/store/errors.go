package store

import "errors"

// Store-level errors are sentinels rather than formatted strings so callers can
// map them to a status code without matching on message text.
//
// Every disabled-path return used to be an independently formatted error
// carrying the same text, so errors.Is could never match it, the API layer could
// only surface it as a 500 with an internal message in the body, and the brand
// handlers answered "brand not found" for a store that had never been consulted.
var (
	// ErrDisabled reports that the store exists but is not usable — never
	// opened, or already closed.
	ErrDisabled = errors.New("sqlite store disabled")

	// ErrBrandNotFound reports that no trusted brand has the requested id. It is
	// distinct from ErrDisabled so a caller can tell a missing row from an
	// unreachable database.
	ErrBrandNotFound = errors.New("brand not found")

	// ErrInvalidBrand reports a brand that failed validation. The wrapped detail
	// describes the caller's own input, so HTTP layers may echo it; anything
	// not wrapping this sentinel must not be echoed.
	ErrInvalidBrand = errors.New("invalid brand")
)

// Telemetry retention bounds.
//
// They live here, and not in the API, because retention is read from two places
// the API does not control: the constructor argument, and the stored value
// re-read at boot. Clamping only in the request validator left a database that
// already held an absurd value reapplying it on every restart.
//
// The ceiling is not cosmetic. Retention feeds a date subtraction: 2e9 days
// puts the cutoff in the year -5473788, and SQLite compares these ISO timestamps
// as TEXT, so "-" sorts before "2" and "analyzed_at < cutoff" matches nothing.
// The DELETE then removes zero rows, the caller logs nothing because it only
// logs when rows > 0, and the table grows without bound.
const (
	MinRetentionDays     = 1
	MaxRetentionDays     = 3650 // ten years
	DefaultRetentionDays = 30
)

// ClampRetentionDays brings a retention value into range and reports whether it
// had to be changed, so the caller can warn about a value that arrived from
// configuration or from an older database rather than silently accepting it.
func ClampRetentionDays(days int) (int, bool) {
	switch {
	case days < MinRetentionDays:
		return DefaultRetentionDays, days != 0
	case days > MaxRetentionDays:
		return MaxRetentionDays, true
	default:
		return days, false
	}
}
