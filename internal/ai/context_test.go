package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestGeminiClassifyDomainRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request generateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if len(request.Contents) == 0 || len(request.Contents[0].Parts) == 0 {
			t.Fatal("expected context classification prompt")
		}

		resp := generateResponse{}
		resp.Candidates = append(resp.Candidates, struct {
			Content struct {
				Parts []part "json:\"parts\""
			} "json:\"content\""
		}{})
		resp.Candidates[0].Content.Parts = append(resp.Candidates[0].Content.Parts, part{Text: `{"role":"victim"}`})
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		Provider:      "gemini",
		GeminiBaseURL: server.URL,
		GeminiAPIKey:  "test-key",
		GeminiTimeout: time.Second,
	})

	role, err := client.ClassifyDomainRole(context.Background(), "legit.example", []string{"evil.example giả mạo legit.example"})
	if err != nil {
		t.Fatal(err)
	}
	if role != DomainRoleVictim {
		t.Fatalf("expected victim, got %s", role)
	}
}

func TestConcurrentGeminiKeyRotationAndContextClassification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := generateResponse{}
		resp.Candidates = append(resp.Candidates, struct {
			Content struct {
				Parts []part "json:\"parts\""
			} "json:\"content\""
		}{})
		resp.Candidates[0].Content.Parts = append(resp.Candidates[0].Content.Parts, part{Text: `{"role":"attacker"}`})
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		Provider:      "gemini",
		GeminiBaseURL: server.URL,
		GeminiAPIKey:  "initial-key",
		GeminiTimeout: time.Second,
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(index int) {
			defer wg.Done()
			client.SetGeminiAPIKey("rotated-key")
		}(i)
		go func() {
			defer wg.Done()
			_, _ = client.ClassifyDomainRole(context.Background(), "evil.example", []string{"evil.example là website giả mạo"})
		}()
	}
	wg.Wait()
}
