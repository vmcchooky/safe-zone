package risk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"safe-zone/internal/store"
)

// URLMLFeedbackConfig configures durable, privacy-safe label correlation.
// When Secret is empty the service keeps the legacy in-memory ring buffer
// (ephemeral, never persisted). When a secret is injected from the
// environment or a *_FILE secret, fingerprints become stable across restarts
// and labels survive process restarts in the bounded SQLite table.
type URLMLFeedbackConfig struct {
	// Secret keys the HMAC fingerprint of the current key version. Required
	// for durable mode; an empty value selects memory mode.
	Secret string
	// KeyVersion tags the active HMAC key so rotations are auditable per row.
	KeyVersion int
	// PreviousSecret optionally retains the prior key for one rotation step so
	// events recorded before a rotation stay correlatable while they age out.
	PreviousSecret string
	// PreviousKeyVersion is the version tag paired with PreviousSecret.
	PreviousKeyVersion int
	// Retention bounds how long feedback rows are kept.
	Retention time.Duration
	// MaxRows caps the retained table size regardless of retention time.
	MaxRows int
}

const (
	defaultURLFeedbackRetentionHours = 168 // 7 days
	defaultURLFeedbackMaxRows        = 65536
	maxURLFeedbackRetentionHours     = 8760
	maxURLFeedbackRows               = 1000000
	urlFeedbackFingerprintBytes      = 16
	urlFeedbackPruneInterval         = 10 * time.Minute
)

func (c URLMLFeedbackConfig) validate() error {
	if c.KeyVersion < 1 || c.KeyVersion > 1000000 {
		return errors.New("URL ML feedback key version must be between 1 and 1000000")
	}
	if c.Retention <= 0 || c.Retention > maxURLFeedbackRetentionHours*time.Hour {
		return errors.New("URL ML feedback retention hours must be between 1 and 8760")
	}
	if c.MaxRows < 100 || c.MaxRows > maxURLFeedbackRows {
		return errors.New("URL ML feedback max rows must be between 100 and 1000000")
	}
	if c.PreviousSecret != "" && (c.PreviousKeyVersion < 1 || c.PreviousKeyVersion > 1000000) {
		return errors.New("URL ML feedback previous key version must be between 1 and 1000000")
	}
	if c.PreviousSecret != "" && c.PreviousKeyVersion == c.KeyVersion {
		return errors.New("URL ML feedback previous key version must differ from the active version")
	}
	return nil
}

// urlFeedbackBackend is the storage contract shared by the ephemeral memory
// buffer and the durable SQLite-backed store. Implementations only ever see
// opaque event IDs; raw URLs are never passed through this interface.
type urlFeedbackBackend interface {
	record(eventID string, probability float64, wouldPromote bool)
	apply(eventID, label string) (bool, string)
	status() URLMLFeedbackStatus
}

type feedbackHMACKey struct {
	version int
	secret  []byte
}

// durableURLFeedbackStore persists keyed HMAC fingerprints plus coarse label
// aggregates in SQLite. Failure semantics are fail closed for feedback only:
// persistence errors reject labels with reason "persistence_error" and drop
// new observations (counted), while domain analysis never touches this path.
type durableURLFeedbackStore struct {
	mu                sync.Mutex
	db                *store.DB
	currentKey        feedbackHMACKey
	previousKey       *feedbackHMACKey
	retention         time.Duration
	maxRows           int
	lastPrune         time.Time
	startupPruned     bool
	persistenceErrors atomic.Int64
}

func newDurableURLFeedbackStore(db *store.DB, cfg URLMLFeedbackConfig) *durableURLFeedbackStore {
	s := &durableURLFeedbackStore{
		db: db,
		currentKey: feedbackHMACKey{
			version: cfg.KeyVersion,
			secret:  []byte(cfg.Secret),
		},
		retention: cfg.Retention,
		maxRows:   cfg.MaxRows,
	}
	if cfg.PreviousSecret != "" {
		s.previousKey = &feedbackHMACKey{
			version: cfg.PreviousKeyVersion,
			secret:  []byte(cfg.PreviousSecret),
		}
	}
	return s
}

func (s *durableURLFeedbackStore) fingerprint(eventID string, key feedbackHMACKey) string {
	mac := hmac.New(sha256.New, key.secret)
	_, _ = mac.Write([]byte(eventID))
	return hex.EncodeToString(mac.Sum(nil)[:urlFeedbackFingerprintBytes])
}

// prune removes expired rows and enforces the row cap. Failures only bump the
// degraded counter; the next window retries.
func (s *durableURLFeedbackStore) prune(now time.Time) {
	ctx, cancel := contextWithTimeout(30 * time.Second)
	defer cancel()
	cutoff := now.Add(-s.retention)
	if _, err := s.db.PruneURLFeedback(ctx, cutoff, s.maxRows); err != nil {
		s.persistenceErrors.Add(1)
	}
}

// record stores a fingerprint for a freshly evaluated shadow observation.
// Unknown/empty event IDs are ignored silently; write failures are counted
// and dropped so analysis traffic is never affected.
func (s *durableURLFeedbackStore) record(eventID string, probability float64, wouldPromote bool) {
	if s == nil || eventID == "" {
		return
	}
	bucket := -1
	if probability >= 0 && probability <= 1 {
		bucket = int(probability * 10)
		if bucket > 9 {
			bucket = 9
		}
	}
	now := time.Now().UTC()
	row := store.URLFeedbackRow{
		Fingerprint:       s.fingerprint(eventID, s.currentKey),
		KeyVersion:        s.currentKey.version,
		ProbabilityBucket: bucket,
		WouldPromote:      wouldPromote,
		RecordedAt:        now,
	}
	ctx, cancel := contextWithTimeout(5 * time.Second)
	defer cancel()
	if err := s.db.UpsertURLFeedback(ctx, row); err != nil {
		s.persistenceErrors.Add(1)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	due := !s.startupPruned || now.Sub(s.lastPrune) >= urlFeedbackPruneInterval
	if due {
		s.startupPruned = true
		s.lastPrune = now
		s.prune(now)
	}
}

// apply correlates a caller-provided label with a previously persisted event.
// The active key is tried first, then the retained previous key so labels
// survive one secret rotation within the retention window.
func (s *durableURLFeedbackStore) apply(eventID, label string) (bool, string) {
	if s == nil || eventID == "" {
		return false, "persistence_error"
	}
	var malicious bool
	switch label {
	case "malicious":
		malicious = true
	case "benign":
	default:
		return false, "invalid_label"
	}

	keys := []feedbackHMACKey{s.currentKey}
	if s.previousKey != nil {
		keys = append(keys, *s.previousKey)
	}
	ctx, cancel := contextWithTimeout(5 * time.Second)
	defer cancel()
	for _, key := range keys {
		err := s.db.ApplyURLFeedbackLabel(ctx, s.fingerprint(eventID, key), malicious)
		switch {
		case err == nil:
			return true, ""
		case errors.Is(err, store.ErrAlreadyLabelled):
			return false, "already_labeled"
		case errors.Is(err, sql.ErrNoRows):
			continue
		default:
			s.persistenceErrors.Add(1)
			return false, "persistence_error"
		}
	}
	return false, "unknown_event"
}

// status reports aggregate counters computed over retained rows. A read
// failure degrades the status but never exposes more than coarse counts.
func (s *durableURLFeedbackStore) status() URLMLFeedbackStatus {
	if s == nil {
		return URLMLFeedbackStatus{Supported: false}
	}
	status := URLMLFeedbackStatus{
		Supported:      true,
		Persistence:    "sqlite",
		KeyVersion:     s.currentKey.version,
		RetentionHours: int(s.retention / time.Hour),
		MaxRows:        s.maxRows,
		Note:           "opaque HMAC fingerprints only; durable bounded SQLite retention",
	}
	if s.previousKey != nil {
		status.PreviousKeyVersion = s.previousKey.version
	}
	ctx, cancel := contextWithTimeout(5 * time.Second)
	defer cancel()
	stats, err := s.db.URLFeedbackStats(ctx)
	if err != nil {
		status.Degraded = true
		status.PersistenceErrors = s.persistenceErrors.Load()
		return status
	}
	status.RecordedEvents = stats.Rows
	status.LabelledEvents = stats.Labeled
	status.ConfirmedMalicious = stats.ConfirmedMalicious
	status.ReportedBenignFalsePositive = stats.ReportedBenignFP
	status.WouldPromoteLabelled = stats.WouldPromoteLabelled
	status.PersistenceErrors = s.persistenceErrors.Load()
	if stats.WouldPromoteLabelled > 0 {
		status.LabelledFalsePositiveRate = float64(stats.ReportedBenignFP) / float64(stats.WouldPromoteLabelled)
	}
	return status
}

// contextWithTimeout mirrors the short timeouts used by other store helpers;
// it lives here to keep the feedback path independent of request contexts.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
