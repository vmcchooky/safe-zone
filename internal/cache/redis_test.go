package cache

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRedisPublishJSONAndSubscribeRoundTrip(t *testing.T) {
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

	ch, closeSub, err := redisCache.Subscribe(context.Background(), "safe-zone:test:channel")
	if err != nil {
		t.Fatal(err)
	}

	payload := struct {
		Type     string `json:"type"`
		Revision string `json:"revision"`
		Source   string `json:"source"`
	}{
		Type:     "analysis_config_updated",
		Revision: "abc123",
		Source:   "core-api",
	}
	if err := redisCache.PublishJSON(context.Background(), "safe-zone:test:channel", payload); err != nil {
		t.Fatal(err)
	}

	select {
	case raw, ok := <-ch:
		if !ok {
			t.Fatal("subscription channel closed before delivering message")
		}

		var got struct {
			Type     string `json:"type"`
			Revision string `json:"revision"`
			Source   string `json:"source"`
		}
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("expected valid JSON payload, got %q: %v", raw, err)
		}
		if got != payload {
			t.Fatalf("unexpected payload: got %#v want %#v", got, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published message")
	}

	if err := closeSub(); err != nil {
		t.Fatal(err)
	}

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected subscription channel to close after cleanup")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for subscription cleanup")
	}
}

func TestRedisPubSubDisabled(t *testing.T) {
	redisCache := NewRedis("", "", 0)

	if err := redisCache.PublishJSON(context.Background(), "safe-zone:test:channel", map[string]string{"type": "noop"}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled from PublishJSON, got %v", err)
	}

	ch, closeSub, err := redisCache.Subscribe(context.Background(), "safe-zone:test:channel")
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled from Subscribe, got %v", err)
	}
	if ch != nil {
		t.Fatal("expected nil subscription channel when redis is disabled")
	}
	if closeSub != nil {
		t.Fatal("expected nil cleanup func when redis is disabled")
	}
}
