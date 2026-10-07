package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// This directory had no tests, which left the ZSCAN walk and its score parsing
// uncovered. The retention rule also deserved a test: the sample was truncated to
// the cap only after the whole walk, so peak memory scaled with the whole refused
// backlog rather than with the cap — and a large backlog is exactly the condition
// that makes an operator run this tool.

// refusedFixtureMembers are bare public suffixes. A member equal to its own public
// suffix is refused, because a block on it would apply to the whole namespace.
// They come from the real suffix list rather than a synthetic pattern, since the
// admissibility check consults that list.
var refusedFixtureMembers = []string{
	"com", "net", "org", "info", "biz", "io", "dev", "app", "co", "uk", "de", "fr",
	"jp", "ru", "cn", "br", "in", "au", "ca", "nl", "se", "no", "fi", "dk", "pl",
	"es", "it", "ch", "at", "be", "cz", "nz", "za", "kr", "mx", "ar", "cl", "tr",
	"vn", "ph", "id", "th", "my", "sg", "hk", "tw", "il", "pt", "gr", "ro", "hu",
}

func seedFeed(t *testing.T, server *miniredis.Miniredis, refused, admissible int) {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	expiry := float64(time.Now().Add(24 * time.Hour).Unix())
	members := make([]redis.Z, 0, refused+admissible)
	for i := 0; i < refused; i++ {
		members = append(members, redis.Z{
			Score:  expiry,
			Member: refusedFixtureMembers[i%len(refusedFixtureMembers)],
		})
	}
	for i := 0; i < admissible; i++ {
		members = append(members, redis.Z{Score: expiry, Member: fmt.Sprintf("ok%d.example", i)})
	}
	if err := client.ZAdd(context.Background(), "test:threat:feed", members...).Err(); err != nil {
		t.Fatalf("seed feed: %v", err)
	}
}

func testRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

// The sample must stop growing at the cap while the count stays exact. The count is
// what an operator sizes a purge from, so it cannot be capped alongside the sample.
func TestScanRefusedBoundsTheSampleButCountsEveryRefusal(t *testing.T) {
	server, client := testRedis(t)

	const sampleCap = 7
	const refused = 50
	seedFeed(t, server, refused, 30)

	sample, total, err := scanRefusedCapped(context.Background(), client, "test:threat:feed", sampleCap)
	if err != nil {
		t.Fatalf("scanRefusedCapped: %v", err)
	}
	if len(sample) != sampleCap {
		t.Fatalf("retained %d members, want exactly the cap of %d", len(sample), sampleCap)
	}
	if total != refused {
		t.Fatalf("counted %d refused members, want %d", total, refused)
	}
}

// The default entry point must apply the production cap.
func TestScanRefusedUsesTheProductionSampleCap(t *testing.T) {
	server, client := testRedis(t)
	seedFeed(t, server, 25, 5)

	sample, total, err := scanRefused(context.Background(), client, "test:threat:feed")
	if err != nil {
		t.Fatalf("scanRefused: %v", err)
	}
	if total != 25 {
		t.Fatalf("counted %d refused, want 25", total)
	}
	if len(sample) > sampleCap {
		t.Fatalf("retained %d members, want at most the production cap of %d", len(sample), sampleCap)
	}
}

// Every retained member must actually be refused. Applying the cap before the
// admissibility check would let admissible domains displace refused ones, and an
// operator would purge the wrong things.
func TestScanRefusedSampleContainsOnlyRefusedMembers(t *testing.T) {
	server, client := testRedis(t)
	seedFeed(t, server, len(refusedFixtureMembers), len(refusedFixtureMembers))

	sample, total, err := scanRefusedCapped(context.Background(), client, "test:threat:feed", 1000)
	if err != nil {
		t.Fatalf("scanRefusedCapped: %v", err)
	}
	if total != len(refusedFixtureMembers) {
		t.Fatalf("counted %d refused, want %d", total, len(refusedFixtureMembers))
	}
	if len(sample) != total {
		t.Fatalf("retained %d, want all %d below the cap", len(sample), total)
	}
	for _, v := range sample {
		if v.Domain == "" {
			t.Fatal("sample contains an empty domain")
		}
		// Admissible fixtures end in ".example"; none may appear here.
		if len(v.Domain) > 8 && v.Domain[len(v.Domain)-8:] == ".example" {
			t.Fatalf("admissible member %q appeared in the refused sample", v.Domain)
		}
	}
}

// An empty or absent key reports zero without error.
func TestScanRefusedOnAnEmptyOrMissingKey(t *testing.T) {
	_, client := testRedis(t)

	for _, key := range []string{"test:empty", "test:does-not-exist"} {
		sample, total, err := scanRefused(context.Background(), client, key)
		if err != nil {
			t.Fatalf("%s: scanRefused: %v", key, err)
		}
		if len(sample) != 0 || total != 0 {
			t.Fatalf("%s: got %d sampled and %d counted, want zero", key, len(sample), total)
		}
	}
}
