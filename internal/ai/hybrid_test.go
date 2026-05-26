package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"safe-zone/internal/analysis"
)

func TestHybridOllamaSuccessNoGeminiCall(t *testing.T) {
	// 1. Mock Ollama Server
	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ollamaGenerateResponse{
			Model:    "gemma2:2b",
			Response: `{"verdict": "MALICIOUS", "confidence": 0.88, "category": "malware", "reason": "offline match"}`,
			Done:     true,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ollamaServer.Close()

	// 2. Mock Gemini Server - should NOT be called
	geminiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Gemini API should not be called when Ollama succeeds")
	}))
	defer geminiServer.Close()

	client := NewClient(Config{
		Provider:      "hybrid",
		GeminiBaseURL: geminiServer.URL + "/v1beta",
		GeminiAPIKey:  "dummy-gemini-key",
		GeminiModel:   "gemini-2.5-flash-lite",
		GeminiTimeout: time.Second,
		OllamaBaseURL: ollamaServer.URL,
		OllamaModel:   "gemma2:2b",
		OllamaTimeout: time.Second,
	})

	if !client.Enabled() {
		t.Fatal("expected hybrid client to be enabled")
	}

	currentResult := analysis.Result{
		Domain:  "malware-site.net",
		Verdict: analysis.VerdictSuspicious,
		Score:   50,
	}

	result, err := client.Refine(context.Background(), currentResult.Domain, currentResult)
	if err != nil {
		t.Fatalf("unexpected error in hybrid mode: %v", err)
	}

	if result.Verdict != analysis.VerdictMalicious {
		t.Errorf("expected MALICIOUS, got %s", result.Verdict)
	}
	if result.Score != 85 {
		t.Errorf("expected score 85, got %d", result.Score)
	}
	if result.Confidence != 0.88 {
		t.Errorf("expected confidence 0.88, got %f", result.Confidence)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != "local offline ai classification: offline match" {
		t.Errorf("unexpected reasons: %v", result.Reasons)
	}
}

func TestHybridOllamaFailsFallbackToGemini(t *testing.T) {
	// 1. Mock Ollama Server - returns HTTP 500
	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ollamaServer.Close()

	// 2. Mock Gemini Server - should succeed
	geminiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := generateResponse{}
		resp.Candidates = append(resp.Candidates, struct {
			Content struct {
				Parts []part "json:\"parts\""
			} "json:\"content\""
		}{})
		resp.Candidates[0].Content.Parts = append(resp.Candidates[0].Content.Parts, part{
			Text: `{"verdict": "MALICIOUS", "confidence": 0.99, "category": "phishing", "reason": "cloud match"}`,
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer geminiServer.Close()

	client := NewClient(Config{
		Provider:      "hybrid",
		GeminiBaseURL: geminiServer.URL,
		GeminiAPIKey:  "dummy-gemini-key",
		GeminiModel:   "gemini-2.5-flash-lite",
		GeminiTimeout: time.Second,
		OllamaBaseURL: ollamaServer.URL,
		OllamaModel:   "gemma2:2b",
		OllamaTimeout: time.Second,
	})

	currentResult := analysis.Result{
		Domain:  "phish-site.org",
		Verdict: analysis.VerdictSuspicious,
		Score:   50,
	}

	result, err := client.Refine(context.Background(), currentResult.Domain, currentResult)
	if err != nil {
		t.Fatalf("unexpected error in fallback hybrid mode: %v", err)
	}

	if result.Verdict != analysis.VerdictMalicious {
		t.Errorf("expected MALICIOUS, got %s", result.Verdict)
	}
	if result.Score != 85 {
		t.Errorf("expected score 85, got %d", result.Score)
	}
	if result.Confidence != 0.99 {
		t.Errorf("expected confidence 0.99, got %f", result.Confidence)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != "local ai classification: cloud match" {
		t.Errorf("unexpected reasons: %v", result.Reasons)
	}
}
