package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"
)

// bearerPrefix is the only credential shape these services accept. Anything
// else -- Basic, a bare token, a cookie -- is rejected without inspection.
const bearerPrefix = "Bearer "

// HasBearerPrefix reports whether the Authorization header carries a Bearer
// credential at all. Callers use it to tell "presented a credential that was
// wrong" apart from "presented no credential", because the two deserve
// different handling: a wrong Bearer token must fail closed rather than fall
// through to a weaker path such as a session cookie.
func HasBearerPrefix(header string) bool {
	return strings.HasPrefix(header, bearerPrefix)
}

// MatchesBearer reports whether header presents the configured admin API key.
//
// It is the single definition of that check. core-api and dns-resolver both
// gate /metrics with it, and core-api's two auth paths call it so the
// enforcing and the annotating variant cannot drift apart; keeping one copy
// is what makes it safe to add a third caller.
//
// An empty presented token and an empty configured key never match. Without
// that guard the comparison degenerates to sha256("") == sha256(""), which
// authenticates a bare "Authorization: Bearer " header as admin on every
// gated route whenever the key is unset (e.g. an embedder that constructs
// handlers.Config itself, or a resolver wired without a key).
//
// The comparison runs over SHA-256 digests with ConstantTimeCompare so it
// leaks neither length nor byte-position information through timing.
func MatchesBearer(header, configuredKey string) bool {
	if configuredKey == "" {
		return false
	}
	if !HasBearerPrefix(header) {
		return false
	}
	token := strings.TrimPrefix(header, bearerPrefix)
	if token == "" {
		return false
	}

	tokenHash := sha256.Sum256([]byte(token))
	expectedHash := sha256.Sum256([]byte(configuredKey))
	return subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1
}
