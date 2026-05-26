package agent

import (
	"context"
	"testing"

	"safe-zone/internal/store"
)

func TestFeedSyncTaskName(t *testing.T) {
	task := NewFeedSyncTask(nil, FeedSyncConfig{})
	if task.Name() != "feedsync" {
		t.Errorf("expected name 'feedsync', got %q", task.Name())
	}
}

func TestFeedSyncTaskNoSources(t *testing.T) {
	task := NewFeedSyncTask(nil, FeedSyncConfig{})
	err := task.Run(context.Background())
	if err != nil {
		t.Errorf("expected nil error for empty sources, got %v", err)
	}
}

func TestFeedSyncTaskNoRedis(t *testing.T) {
	task := NewFeedSyncTask(nil, FeedSyncConfig{
		Sources:   []string{"https://example.com/feed.txt"},
		RedisAddr: "", // no redis
	})
	err := task.Run(context.Background())
	if err != nil {
		t.Errorf("expected nil error when Redis not configured, got %v", err)
	}
}

func TestFeedSyncTaskEmptySourcesFiltered(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer db.Close()

	task := NewFeedSyncTask(db, FeedSyncConfig{
		Sources:   []string{"", "  ", ""},
		RedisAddr: "localhost:6379",
	})

	// All sources are empty after trimming, so no actual sync happens.
	// This won't error because there are no valid sources to process.
	// (It would fail trying to connect to Redis if there were valid sources,
	// but empty sources are filtered out.)
	err = task.Run(context.Background())
	if err != nil {
		t.Errorf("expected nil error for all-empty sources, got %v", err)
	}
}

func TestFeedSyncTaskSourceParsing(t *testing.T) {
	cfg := FeedSyncConfig{
		Sources: []string{
			"https://phishtank.org/data.txt",
			"https://urlhaus.abuse.ch/downloads/text/",
			"https://openphish.com/feed.txt",
		},
		RedisAddr: "localhost:6379",
	}

	task := NewFeedSyncTask(nil, cfg)
	if len(task.config.Sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(task.config.Sources))
	}
}
