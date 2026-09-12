package main

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// The growth tripwire fires only above the configured threshold so normal
// feed sizes stay silent.
func TestWarnIfFeedOversized(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	direct := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer func() { _ = direct.Close() }()
	for _, member := range []string{"a.test", "b.test", "c.test"} {
		if err := direct.ZAdd(context.Background(), "warn-key", redis.Z{Score: 1, Member: member}).Err(); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("SAFE_ZONE_FEED_MAX_MEMBERS_WARN", "2")
	if !warnIfFeedOversized(context.Background(), server.Addr(), "", 0, "warn-key") {
		t.Fatal("expected oversize warning above threshold")
	}
	t.Setenv("SAFE_ZONE_FEED_MAX_MEMBERS_WARN", "100")
	if warnIfFeedOversized(context.Background(), server.Addr(), "", 0, "warn-key") {
		t.Fatal("no warning expected under threshold")
	}
}
