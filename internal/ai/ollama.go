package ai

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"safe-zone/internal/analysis"
)

// OllamaClient implements Provider for a local Ollama server running offline.
type OllamaClient struct {
	baseURL string
	model   string
	timeout time.Duration
	http    *http.Client
}

type ollamaGenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
	Format string `json:"format"` // Natively forces structured JSON output
}

type ollamaGenerateResponse struct {
	Model    string `json:"model"`
	Response string `json:"response"` // Contains the raw JSON string returned by the model
	Done     bool   `json:"done"`
}

// NewOllamaClient initializes an offline AI client for the local Ollama daemon.
func NewOllamaClient(baseURL, model string, timeout time.Duration) *OllamaClient {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	model = strings.TrimSpace(model)
	if model == "" {
		model = "gemma2:2b"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &OllamaClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		timeout: timeout,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
}

// Enabled implements Provider. Ollama is enabled if a valid baseURL is provided.
func (o *OllamaClient) Enabled() bool {
	return o != nil && o.baseURL != "" && o.http != nil
}

// Refine implements Provider, performing local threat classification.
func (o *OllamaClient) Refine(ctx context.Context, domain string, current analysis.Result) (analysis.Result, error) {
	if !o.Enabled() {
		return analysis.Result{}, errors.New("ollama provider disabled")
	}

	prompt := buildPrompt(domain, current)
	text, err := o.generateText(ctx, prompt)
	if err != nil {
		return analysis.Result{}, err
	}

	var parsed Result
	if err := json.Unmarshal([]byte(extractJSON(text)), &parsed); err != nil {
		return analysis.Result{}, fmt.Errorf("invalid ollama response JSON: %w (raw: %s)", err, text)
	}

	result := analysis.Result{Domain: current.Domain}
	switch strings.ToUpper(strings.TrimSpace(parsed.Verdict)) {
	case string(analysis.VerdictMalicious):
		result.Verdict = analysis.VerdictMalicious
		result.Score = 85
	case string(analysis.VerdictSuspicious):
		result.Verdict = analysis.VerdictSuspicious
		result.Score = 55
	default:
		result.Verdict = analysis.VerdictSafe
		result.Score = 0
	}

	if parsed.Confidence < 0 {
		parsed.Confidence = 0
	}
	if parsed.Confidence > 1 {
		parsed.Confidence = 1
	}
	result.Confidence = parsed.Confidence
	if parsed.Reason != "" {
		result.Reasons = []string{"local offline ai classification: " + parsed.Reason}
	}

	// Set category from parsed response or fallback to local heuristics
	parsedCategory := strings.ToLower(strings.TrimSpace(parsed.Category))
	if parsedCategory != "" && parsedCategory != "uncategorized" {
		result.Category = parsedCategory
	} else {
		result.Category = analysis.ClassifyCategory(domain)
	}

	return result, nil
}

func (o *OllamaClient) generateText(ctx context.Context, prompt string) (string, error) {
	if !o.Enabled() {
		return "", errors.New("ollama provider disabled")
	}

	reqBody, err := json.Marshal(ollamaGenerateRequest{
		Model:  o.model,
		Prompt: prompt,
		Stream: false,
		Format: "json", // Instructs Ollama to guarantee structured JSON output
	})
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	requestURL := fmt.Sprintf("%s/api/generate", o.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling local ollama failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("ollama returned HTTP %d", resp.StatusCode)
	}

	var envelope ollamaGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return "", err
	}

	return envelope.Response, nil
}
