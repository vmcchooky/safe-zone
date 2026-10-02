package analysis

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// IsRegistrableDomain reports whether a domain has a registrable label, that
// is whether EffectiveTLDPlusOne can identify one.
//
// A public suffix ("com", "co.uk", "github.io") is not a domain anybody can
// register, so it is never a valid target for a rule that applies to a domain
// and its subdomains. Storing one is a mistake with a very large blast radius:
// a parent-suffix lookup matches the entry against every domain beneath it, so
// a single row for "com" applies to all of .com. On the allow side that
// silently disables protection for the namespace; on the block side it blocks
// it. Both short-circuit the layers that come after.
func IsRegistrableDomain(domain string) bool {
	normalized, err := NormalizeDomain(domain)
	if err != nil || normalized == "" {
		return false
	}
	_, err = publicsuffix.EffectiveTLDPlusOne(normalized)
	return err == nil
}

// RegistrableWalkFloor returns how many parent labels a parent-suffix lookup
// may skip for a domain. The registrable label (eTLD+1) is the floor, so
// "login.example.co.uk" yields 1 and only "example.co.uk" is reachable.
//
// Zero means "no parent may be considered": the domain is already at or below
// the floor, or it is not registrable. Callers must never walk past this, or a
// public-suffix row would be applied to the whole namespace.
//
// Shared by every parent-suffix lookup in the codebase (whitelist, admin
// override) so the floor is defined once.
func RegistrableWalkFloor(domain string) int {
	normalized, err := NormalizeDomain(domain)
	if err != nil || normalized == "" {
		return 0 // no usable floor: consider the domain itself only
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(normalized)
	if err != nil {
		return 0
	}
	floorLabels := strings.Count(registrable, ".") + 1
	labels := strings.Count(normalized, ".") + 1
	if floorLabels >= labels {
		return 0 // already at or above the floor
	}
	return labels - floorLabels
}
