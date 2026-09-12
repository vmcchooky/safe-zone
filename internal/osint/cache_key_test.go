package osint

import (
	"testing"
)

// M2: the evidence cache key must scope the producer configuration, so a
// source/trust-list change cannot reuse reports fetched under another one.
func TestEvidenceCacheKeyScopesConfig(t *testing.T) {
	a := NewService(Options{Enabled: true, Sources: []string{"https://a.test/warn"}})
	b := NewService(Options{Enabled: true, Sources: []string{"https://b.test/warn"}})
	c := NewService(Options{Enabled: true, Sources: []string{"https://a.test/warn"}})

	if a.evidenceCacheKey("evil.example") == b.evidenceCacheKey("evil.example") {
		t.Fatal("different source sets must produce different cache keys")
	}
	if a.evidenceCacheKey("evil.example") != c.evidenceCacheKey("evil.example") {
		t.Fatal("identical configs must produce identical cache keys")
	}
	if a.evidenceCacheKey("evil.example") == a.evidenceCacheKey("other.example") {
		t.Fatal("different domains must produce different cache keys")
	}
}
