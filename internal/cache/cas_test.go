package cache

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

// PR-05/M1: the conditional write must be atomic and honor refusals.
func TestCompareAndSwapJSONSemantics(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	redisCache := NewRedis(server.Addr(), "", 0)
	defer func() {
		if err := redisCache.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	ctx := context.Background()

	approve := func(raw []byte, found bool) (bool, error) { return true, nil }
	refuse := func(raw []byte, found bool) (bool, error) { return false, nil }

	swapped, err := redisCache.CompareAndSwapJSON(ctx, "cas:key", approve, map[string]int{"n": 1}, 0)
	if err != nil || !swapped {
		t.Fatalf("absent key must be written, swapped=%v err=%v", swapped, err)
	}

	swapped, err = redisCache.CompareAndSwapJSON(ctx, "cas:key", refuse, map[string]int{"n": 2}, 0)
	if err != nil || swapped {
		t.Fatalf("refused swap must leave entry, swapped=%v err=%v", swapped, err)
	}
	var kept map[string]int
	found, err := redisCache.GetJSON(ctx, "cas:key", &kept)
	if err != nil || !found || kept["n"] != 1 {
		t.Fatalf("entry changed after refusal: %+v found=%v err=%v", kept, found, err)
	}

	boom := errors.New("swap boom")
	if _, err := redisCache.CompareAndSwapJSON(ctx, "cas:key",
		func(raw []byte, found bool) (bool, error) { return false, boom },
		map[string]int{"n": 3}, 0); !errors.Is(err, boom) {
		t.Fatalf("swap error must propagate, got %v", err)
	}

	disabled := NewRedis("", "", 0)
	if _, err := disabled.CompareAndSwapJSON(ctx, "cas:key", approve, 1, 0); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled CAS err = %v; want ErrDisabled", err)
	}
}

// PR-05/M1: concurrent increments through CAS must converge exactly —
// last-writer-wins would silently drop increments.
func TestCompareAndSwapJSONConcurrent(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	redisCache := NewRedis(server.Addr(), "", 0)
	defer func() {
		if err := redisCache.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	ctx := context.Background()

	const workers = 20
	var failures atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < 200; attempt++ {
				var observed int
				found, err := redisCache.GetJSON(ctx, "cas:counter", &observed)
				if err != nil {
					failures.Add(1)
					return
				}
				swapped, err := redisCache.CompareAndSwapJSON(ctx, "cas:counter",
					func(raw []byte, present bool) (bool, error) {
						if present != found {
							return false, nil
						}
						current := 0
						if present {
							if err := json.Unmarshal(raw, &current); err != nil {
								return false, err
							}
						}
						return current == observed, nil
					}, observed+1, 0)
				if err != nil && !errors.Is(err, ErrCASConflict) {
					failures.Add(1)
					return
				}
				if swapped {
					return
				}
			}
			failures.Add(1)
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("unexpected CAS failures: %d", failures.Load())
	}
	var total int
	found, err := redisCache.GetJSON(ctx, "cas:counter", &total)
	if err != nil || !found || total != workers {
		t.Fatalf("counter = %d found=%v err=%v; want %d", total, found, err, workers)
	}
}
