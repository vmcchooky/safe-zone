package risk

import (
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/store"
)

// Close used to be a bare `close(s.enrichDone)`, so a second call panicked with
// "close of closed channel". That is reachable in practice: a caller that
// defers Close and also shuts down explicitly, or two owners of the same
// service, is enough.
func TestServiceCloseIsIdempotent(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "close.db"), 30)
	if err != nil {
		t.Fatal(err)
	}

	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              db,
		AdblockFileRoot:    t.TempDir(),
		DisableAdblockSync: true,
	})

	// Enrichment must be running for the channel to exist, which is the
	// pre-condition for the panic.
	if svc.enrichDone == nil {
		t.Fatal("precondition: the enrichment completion channel should exist")
	}

	for i := range 5 {
		if err := svc.Close(); err != nil {
			t.Fatalf("Close call %d: %v", i+1, err)
		}
	}
}

// A nil service must stay safe: several constructors and handlers guard on it.
func TestNilServiceCloseIsSafe(t *testing.T) {
	var svc *Service
	if err := svc.Close(); err != nil {
		t.Fatalf("nil Close = %v, want nil", err)
	}
}

// Closing concurrently is also a realistic shape (a defer racing an explicit
// shutdown), and must not panic.
func TestServiceCloseIsSafeUnderConcurrency(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "close-race.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              db,
		AdblockFileRoot:    t.TempDir(),
		DisableAdblockSync: true,
	})

	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			_ = svc.Close()
		}()
	}
	for range 8 {
		<-done
	}
}
