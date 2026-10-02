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

	// Per-operation budgets layered on top of the caller's context, so a
	// store call can never outlive its request by more than this.
	urlFeedbackWriteTimeout  = 5 * time.Second
	urlFeedbackStatusTimeout = 5 * time.Second
	urlFeedbackPruneTimeout  = 30 * time.Second
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
//
// Every method takes the caller's context. The durable store used to build its
// own from context.Background with a comment about staying "independent of
// request contexts" — which meant a caller who had already gone away still left
// a write queued on the single SQLite connection for up to five seconds, and
// the status read kept running after the request that wanted it had finished.
// The memory implementation ignores it, which is why the contract can carry it
// without burden.
type urlFeedbackBackend interface {
	record(ctx context.Context, eventID string, probability float64, wouldPromote bool)
	apply(ctx context.Context, eventID, label string) (bool, string)
	status(ctx context.Context) URLMLFeedbackStatus
	// waitForPrune blocks until any background retention work has finished, so
	// the service can close the store without pulling it out from under a
	// running query. The memory implementation has no background work.
	waitForPrune()
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
	// lifecycle stops the background sweeper on shutdown. Without it a prune
	// already handed to a goroutine would outlive the service.
	lifecycle context.Context
	// pruneInflight keeps at most one background prune in flight, so a burst of
	// records cannot fan out into a burst of prunes on the same connection.
	pruneInflight atomic.Bool
	// pruneWG lets Close wait for an in-flight prune. Without it the store can
	// be closed while a prune is still querying, which surfaces as a
	// "database is closed" error counted into persistenceErrors after the
	// service is already gone.
	pruneWG sync.WaitGroup
}

func newDurableURLFeedbackStore(db *store.DB, cfg URLMLFeedbackConfig, lifecycle context.Context) *durableURLFeedbackStore {
	if lifecycle == nil {
		lifecycle = context.Background()
	}
	s := &durableURLFeedbackStore{
		db:        db,
		lifecycle: lifecycle,
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
func (s *durableURLFeedbackStore) prune(ctx context.Context, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, urlFeedbackPruneTimeout)
	defer cancel()
	cutoff := now.Add(-s.retention)
	if _, err := s.db.PruneURLFeedback(ctx, cutoff, s.maxRows); err != nil {
		s.persistenceErrors.Add(1)
	}
}

// record stores a fingerprint for a freshly evaluated shadow observation.
// Unknown/empty event IDs are ignored silently; write failures are counted
// and dropped so analysis traffic is never affected.
//
// ctx bounds the write. It used to be backgrounded outright, which meant a
// caller who had already gone away still left a write queued on the single
// SQLite connection for up to five seconds — the same disconnection problem the
// decision pipeline threads its context through to avoid.
func (s *durableURLFeedbackStore) record(ctx context.Context, eventID string, probability float64, wouldPromote bool) {
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
	writeCtx, cancel := context.WithTimeout(ctx, urlFeedbackWriteTimeout)
	defer cancel()
	if err := s.db.UpsertURLFeedback(writeCtx, row); err != nil {
		s.persistenceErrors.Add(1)
		return
	}
	s.maybePrune(ctx, now)
}

// maybePrune claims the pruning slot and hands the work to the background
// sweeper.
//
// The prune used to run inline, on the request path, while holding the store
// mutex and against a context with a thirty-second budget. So once every ten
// minutes one analysis request held the mutex and the single SQLite connection
// for up to thirty seconds, and every other record queued behind it. Pruning is
// retention housekeeping and nothing waits on its result, so it belongs on a
// goroutine that the request hands off to and forgets.
//
// The in-flight claim comes FIRST. An earlier version marked startupPruned and
// stamped lastPrune, and only then tried the claim — so a record that arrived
// while another prune was running consumed the slot and started nothing. The
// consequence was the exact case startupPruned exists to prevent: no prune at
// all for the next ten minutes, and indefinitely under sustained load.
// Checking "is it due" first, then claiming, then stamping, means a failed claim
// leaves the schedule untouched and the next record retries.
func (s *durableURLFeedbackStore) maybePrune(ctx context.Context, now time.Time) {
	s.mu.Lock()
	due := !s.startupPruned || now.Sub(s.lastPrune) >= urlFeedbackPruneInterval
	s.mu.Unlock()
	if !due {
		return
	}
	s.backgroundPrune(ctx, now)
}

// apply correlates a caller-provided label with a previously persisted event.
// The active key is tried first, then the retained previous key so labels
// survive one secret rotation within the retention window.
func (s *durableURLFeedbackStore) apply(ctx context.Context, eventID, label string) (bool, string) {
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
	labelCtx, cancel := context.WithTimeout(ctx, urlFeedbackWriteTimeout)
	defer cancel()
	for _, key := range keys {
		err := s.db.ApplyURLFeedbackLabel(labelCtx, s.fingerprint(eventID, key), malicious)
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
func (s *durableURLFeedbackStore) status(ctx context.Context) URLMLFeedbackStatus {
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
	statusCtx, cancel := context.WithTimeout(ctx, urlFeedbackStatusTimeout)
	defer cancel()
	stats, err := s.db.URLFeedbackStats(statusCtx)
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

// backgroundPrune runs a retention prune off the request path.
//
// The triggering request's context is deliberately *not* used to bound the work.
// ctx is the triggering request's context. It is cancelled the moment a DoH
// client disconnects, and a request routinely finishes while a prune is still
// querying — so a prune bound to ctx would be cancelled by an unrelated client
// hanging up, and retention housekeeping would silently never complete under
// load. The request is therefore used only to detect "already gone away" at the
// moment of hand-off.
//
// What actually bounds a running prune is s.lifecycle, so shutdown can cut a
// prune short instead of waiting out its full budget, and the prune's own
// deadline as a backstop.
func (s *durableURLFeedbackStore) backgroundPrune(ctx context.Context, now time.Time) {
	if s == nil {
		return
	}
	select {
	case <-s.lifecycle.Done():
		return
	case <-ctx.Done():
		return
	default:
	}
	if !s.pruneInflight.CompareAndSwap(false, true) {
		// Another prune owns the slot. Leave startupPruned and lastPrune
		// untouched so the next record retries instead of waiting out a full
		// interval for work that never started.
		return
	}

	// The WaitGroup is incremented here, before the goroutine can run and
	// before any early return below. Done after the CAS instead, it raced
	// waitForPrune: Close could see a zero counter, return, and close the
	// store while this prune was still about to run against it.
	s.pruneWG.Add(1)

	// Only now that the work is genuinely scheduled is the window advanced.
	s.mu.Lock()
	s.startupPruned = true
	s.lastPrune = now
	s.mu.Unlock()

	// WithoutCancel detaches the request's deadline and cancellation while
	// keeping its values. The prune runs under a context that stops when the
	// service shuts down, and carries its own deadline on top.
	pruneCtx, cancelPrune := context.WithCancel(context.WithoutCancel(ctx))
	stopOnShutdown := context.AfterFunc(s.lifecycle, cancelPrune)

	go func() {
		defer s.pruneWG.Done()
		defer stopOnShutdown()
		defer cancelPrune()
		defer s.pruneInflight.Store(false)
		s.prune(pruneCtx, now)
	}()
}

// waitForPrune blocks until any in-flight background prune has finished, so
// Close cannot close the store while a prune is still querying it.
func (s *durableURLFeedbackStore) waitForPrune() {
	if s == nil {
		return
	}
	s.pruneWG.Wait()
}
