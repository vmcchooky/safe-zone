package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/analysis"
)

func TestRefineParsesMaliciousResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash-lite:generateContent" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("key"); got != "test-key" {
			t.Fatalf("expected api key in query, got %q", got)
		}
		var req generateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if len(req.Contents) != 1 || len(req.Contents[0].Parts) != 1 {
			t.Fatalf("unexpected request contents: %#v", req.Contents)
		}
		if !strings.Contains(req.Contents[0].Parts[0].Text, "secure-login-example.com") {
			t.Fatalf("expected domain in prompt, got %q", req.Contents[0].Parts[0].Text)
		}
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"verdict\":\"MALICIOUS\",\"confidence\":0.91,\"reason\":\"high risk pattern\"}"}]}}]}`))
	}))
	defer server.Close()

	client := New(server.URL+"/v1beta", "test-key", "gemini-2.5-flash-lite", time.Second)
	current := analysis.Result{Domain: "secure-login-example.com", Verdict: analysis.VerdictSuspicious, Confidence: 0.52, Score: 45}
	result, err := client.Refine(context.Background(), current.Domain, current)
	if err != nil {
		t.Fatal(err)
	}

	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict, got %s", result.Verdict)
	}
	if result.Confidence != 0.91 {
		t.Fatalf("expected confidence 0.91, got %.2f", result.Confidence)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != "local ai classification: high risk pattern" {
		t.Fatalf("unexpected reasons: %#v", result.Reasons)
	}
}

func TestRefineDisabled(t *testing.T) {
	client := New("", "", "", time.Second)
	if client.Enabled() {
		t.Fatal("expected disabled client")
	}

	_, err := client.Refine(context.Background(), "example.com", analysis.Result{})
	if err == nil {
		t.Fatal("expected disabled client error")
	}
}

func TestRefineParsesCategoryResponse(t *testing.T) {
	// Case 1: AI returns a specific category
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"verdict\":\"SAFE\",\"confidence\":0.95,\"category\":\"social_media\",\"reason\":\"trusted social network\"}"}]}}]}`))
	}))
	defer server1.Close()

	client1 := New(server1.URL+"/v1beta", "test-key", "gemini-2.5-flash-lite", time.Second)
	res1, err := client1.Refine(context.Background(), "facebook.com", analysis.Result{Domain: "facebook.com"})
	if err != nil {
		t.Fatal(err)
	}
	if res1.Category != "social_media" {
		t.Fatalf("expected category social_media, got %s", res1.Category)
	}

	// Case 2: AI returns uncategorized, fallback to heuristics
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"verdict\":\"SAFE\",\"confidence\":0.80,\"category\":\"uncategorized\",\"reason\":\"general site\"}"}]}}]}`))
	}))
	defer server2.Close()

	client2 := New(server2.URL+"/v1beta", "test-key", "gemini-2.5-flash-lite", time.Second)
	res2, err := client2.Refine(context.Background(), "facebook.com", analysis.Result{Domain: "facebook.com"})
	if err != nil {
		t.Fatal(err)
	}
	// Facebook.com is classified as social_media by local heuristics
	if res2.Category != "social_media" {
		t.Fatalf("expected category to fallback to social_media, got %s", res2.Category)
	}
}
