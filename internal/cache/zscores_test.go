package cache

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// PR-02/H4: batch fan-out must preserve per-member presence and keep
// fail-open behavior for disabled Redis.
func TestZScoresBatchPresence(t *testing.T) {
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
	if _, err := redisCache.ZAdd(ctx, "test:feed", redis.Z{Score: 100, Member: "a.test"}, redis.Z{Score: 50, Member: "c.test"}); err != nil {
		t.Fatal(err)
	}

	scores, ok, err := redisCache.ZScores(ctx, "test:feed", []string{"a.test", "missing.test", "c.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) != 3 || len(ok) != 3 {
		t.Fatalf("lengths = %d/%d; want 3/3", len(scores), len(ok))
	}
	if !ok[0] || scores[0] != 100 || ok[1] || !ok[2] || scores[2] != 50 {
		t.Fatalf("presence/scores wrong: scores=%v ok=%v", scores, ok)
	}

	emptyScores, emptyOK, err := redisCache.ZScores(ctx, "test:feed", nil)
	if err != nil || emptyScores != nil || emptyOK != nil {
		t.Fatalf("empty batch = %v/%v/%v; want nils", emptyScores, emptyOK, err)
	}

	disabled := NewRedis("", "", 0)
	if _, _, err := disabled.ZScores(ctx, "test:feed", []string{"a.test"}); err != ErrDisabled {
		t.Fatalf("disabled batch err = %v; want ErrDisabled", err)
	}
}
