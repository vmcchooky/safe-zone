package risk

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
)

// urlFeedbackStore implements privacy-safe label correlation for URL shadow
// observations. Callers generate an opaque event ID client-side; the server
// keeps only an HMAC fingerprint (with a per-process random salt that is never
// persisted) plus coarse aggregates. No raw URL, query, redirect target or
// credential is ever recorded here. Calibration / FPR numbers are computed
// exclusively from labelled events.
type urlFeedbackStore struct {
	mu        sync.Mutex
	salt      []byte
	capacity  int
	nextSlot  int
	entries   []urlFeedbackEntry
	index     map[urlFeedbackKey]int
	recorded  int64
	labelled  int64
	confirmed int64
	falsePos  int64
	promoted  int64 // labelled events whose shadow action was would-promote
}

type urlFeedbackKey [16]byte

type urlFeedbackEntry struct {
	key            urlFeedbackKey
	probabilityPct int // probability bucket index (0..9), -1 unknown
	wouldPromote   bool
	labeled        bool
	labelMalicious bool
}

func newURLFeedbackStore(capacity int) *urlFeedbackStore {
	if capacity <= 0 {
		capacity = 8192
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		// A deterministic fallback salt still avoids cross-restart linkage
		// because the store itself is memory-only and never persisted.
		for i := range salt {
			salt[i] = byte(i * 7)
		}
	}
	return &urlFeedbackStore{
		salt:     salt,
		capacity: capacity,
		entries:  make([]urlFeedbackEntry, 0, capacity),
		index:    make(map[urlFeedbackKey]int, capacity),
	}
}

func (s *urlFeedbackStore) fingerprint(eventID string) urlFeedbackKey {
	mac := hmac.New(sha256.New, s.salt)
	_, _ = mac.Write([]byte(eventID))
	var key urlFeedbackKey
	copy(key[:], mac.Sum(nil)[:16])
	return key
}

// record stores a fingerprint for a freshly evaluated shadow observation.
// Unknown/empty event IDs are ignored silently.
func (s *urlFeedbackStore) record(eventID string, probability float64, wouldPromote bool) {
	if s == nil || eventID == "" {
		return
	}
	key := s.fingerprint(eventID)
	bucket := -1
	if probability >= 0 && probability <= 1 {
		bucket = int(probability * 10)
		if bucket > 9 {
			bucket = 9
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot, ok := s.index[key]; ok {
		entry := &s.entries[slot]
		entry.probabilityPct = bucket
		entry.wouldPromote = wouldPromote
		return
	}
	if len(s.entries) < s.capacity {
		s.entries = append(s.entries, urlFeedbackEntry{
			key:            key,
			probabilityPct: bucket,
			wouldPromote:   wouldPromote,
		})
	} else {
		evicted := s.entries[s.nextSlot]
		delete(s.index, evicted.key)
		s.entries[s.nextSlot] = urlFeedbackEntry{
			key:            key,
			probabilityPct: bucket,
			wouldPromote:   wouldPromote,
		}
	}
	s.index[key] = s.nextSlot
	s.nextSlot = (s.nextSlot + 1) % s.capacity
	s.recorded++
}

// apply correlates a caller-provided label with a previously recorded event.
func (s *urlFeedbackStore) apply(eventID, label string) (bool, string) {
	if s == nil || eventID == "" {
		return false, "unknown_event"
	}
	key := s.fingerprint(eventID)
	s.mu.Lock()
	defer s.mu.Unlock()
	slot, ok := s.index[key]
	if !ok {
		return false, "unknown_event"
	}
	entry := &s.entries[slot]
	if entry.labeled {
		return false, "already_labeled"
	}
	entry.labeled = true
	switch label {
	case "malicious":
		entry.labelMalicious = true
		s.labelled++
		s.confirmed++
		if entry.wouldPromote {
			s.promoted++
		}
	case "benign":
		entry.labelMalicious = false
		s.labelled++
		if entry.wouldPromote {
			s.promoted++
			s.falsePos++
		}
	default:
		entry.labeled = false
		return false, "invalid_label"
	}
	return true, ""
}

// status returns aggregate counters only. The labelled false-positive rate is
// defined over labelled would-promote events; it is omitted when no such
// labels exist so unlabelled traffic can never imply calibration.
func (s *urlFeedbackStore) status() URLMLFeedbackStatus {
	if s == nil {
		return URLMLFeedbackStatus{Supported: false}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	status := URLMLFeedbackStatus{
		Supported:                   true,
		Capacity:                    s.capacity,
		RecordedEvents:              s.recorded,
		LabelledEvents:              s.labelled,
		ConfirmedMalicious:          s.confirmed,
		ReportedBenignFalsePositive: s.falsePos,
		WouldPromoteLabelled:        s.promoted,
		Note:                        "opaque HMAC fingerprints only; calibration from labelled events",
	}
	if s.promoted > 0 {
		status.LabelledFalsePositiveRate = float64(s.falsePos) / float64(s.promoted)
	}
	return status
}
