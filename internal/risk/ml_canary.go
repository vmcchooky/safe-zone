package risk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"safe-zone/internal/analysis"
)

const mlCanarySelectorAlgorithm = "sha256_normalized_domain_v1"

// MLCanaryConfig bounds ML enforcement to a deterministic percentage of the
// normalized-domain hash space. Domain selection keeps cache behavior
// consistent across clients, core-api, and dns-resolver.
type MLCanaryConfig struct {
	Percent int
	Seed    string
}

type MLCanaryStatus struct {
	Configured          bool   `json:"configured"`
	Algorithm           string `json:"algorithm,omitempty"`
	Percent             int    `json:"percent"`
	SelectorRevision    string `json:"selector_revision,omitempty"`
	SelectedPredictions int64  `json:"selected_predictions"`
	ExcludedPredictions int64  `json:"excluded_predictions"`
	SelectedWouldBlock  int64  `json:"selected_would_block"`
	SelectedWouldPass   int64  `json:"selected_would_pass"`
	EnforceSuppressed   int64  `json:"enforce_suppressed"`
}

func (c MLCanaryConfig) validate() error {
	if c.Percent < 0 || c.Percent > 100 {
		return fmt.Errorf("ML canary percent must be between 0 and 100")
	}
	seed := strings.TrimSpace(c.Seed)
	if c.Percent > 0 && seed == "" {
		return errors.New("ML canary seed is required when percent is greater than zero")
	}
	if len(seed) > 128 {
		return errors.New("ML canary seed must not exceed 128 bytes")
	}
	return nil
}

func (c MLCanaryConfig) enabled() bool {
	return c.Percent > 0 && c.Percent <= 100 && strings.TrimSpace(c.Seed) != ""
}

// Eligible reports whether a normalized domain belongs to this immutable
// canary cohort. Invalid domains and invalid/disabled configs are excluded.
func (c MLCanaryConfig) Eligible(domain string) bool {
	if !c.enabled() {
		return false
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return false
	}
	if c.Percent == 100 {
		return true
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(c.Seed) + "\x00" + normalized))
	bucket := binary.BigEndian.Uint64(sum[:8]) % 10_000
	// #nosec G115 -- enabled validates Percent in the closed interval [1, 100].
	threshold := uint64(c.Percent) * 100
	return bucket < threshold
}

func (c MLCanaryConfig) revision() string {
	if !c.enabled() {
		return ""
	}
	material := fmt.Sprintf("algorithm=%s\npercent=%d\nseed=%s\n", mlCanarySelectorAlgorithm, c.Percent, strings.TrimSpace(c.Seed))
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}
