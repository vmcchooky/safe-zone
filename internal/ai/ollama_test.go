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

func TestOllamaRefineSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Fatalf("unexpected URL path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected HTTP method: %s", r.Method)
		}

		var req ollamaGenerateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}

		if req.Model != "test-ollama-model" {
			t.Errorf("expected model 'test-ollama-model', got '%s'", req.Model)
		}
		if !req.Stream {
			// Ensure streaming is disabled
		}
		if req.Format != "json" {
			t.Errorf("expected format 'json', got '%s'", req.Format)
		}

		resp := ollamaGenerateResponse{
			Model:    req.Model,
			Response: `{"verdict": "MALICIOUS", "confidence": 0.95, "category": "phishing", "reason": "fake login form detected"}`,
			Done:     true,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "test-ollama-model", time.Second)
	if !client.Enabled() {
		t.Fatal("expected ollama client to be enabled")
	}

	currentResult := analysis.Result{
		Domain:  "suspicious-domain.com",
		Verdict: analysis.VerdictSuspicious,
		Score:   50,
	}

	result, err := client.Refine(context.Background(), currentResult.Domain, currentResult)
	if err != nil {
		t.Fatalf("unexpected refine error: %v", err)
	}

	if result.Verdict != analysis.VerdictMalicious {
		t.Errorf("expected verdict MALICIOUS, got %s", result.Verdict)
	}
	if result.Score != 85 {
		t.Errorf("expected score 85, got %d", result.Score)
	}
	if result.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", result.Confidence)
	}
	if len(result.Reasons) != 1 || !strings.Contains(result.Reasons[0], "fake login form detected") {
		t.Errorf("unexpected reasons: %v", result.Reasons)
	}
	if result.Category != "phishing" {
		t.Errorf("expected category 'phishing', got '%s'", result.Category)
	}
}

func TestOllamaRefineHttpError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "test-ollama-model", time.Second)
	_, err := client.Refine(context.Background(), "test.com", analysis.Result{})
	if err == nil {
		t.Fatal("expected error when server returns HTTP 500")
	}
}

func TestOllamaRefineInvalidJson(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ollamaGenerateResponse{
			Model:    "model",
			Response: `invalid-json-string`,
			Done:     true,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "test-ollama-model", time.Second)
	_, err := client.Refine(context.Background(), "test.com", analysis.Result{})
	if err == nil {
		t.Fatal("expected error on invalid JSON response")
	}
}
