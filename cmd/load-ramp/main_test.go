package main

import (
	"sync/atomic"
	"testing"
)

func TestNextIndex(t *testing.T) {
	var cursor atomic.Uint64

	// Edge cases
	if got := nextIndex(&cursor, 0); got != 0 {
		t.Fatalf("expected 0 for pool=0, got %d", got)
	}
	if got := nextIndex(&cursor, -5); got != 0 {
		t.Fatalf("expected 0 for negative pool, got %d", got)
	}

	// Normal cyclical distribution
	cursor.Store(0)
	pool := 3
	for i := 0; i < 9; i++ {
		want := i % pool
		got := nextIndex(&cursor, pool)
		if got != want {
			t.Fatalf("step %d: expected %d, got %d", i, want, got)
		}
	}
}
