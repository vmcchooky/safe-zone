package ai

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
)

const (
	defaultModel   = "gemini-2.5-flash-lite"
	defaultBaseURL = "https://generativelanguage.googleapis.com/v1beta"
)

// Config holds all parameters to initialize the unified AI interface.
type Config struct {
	Provider      string // "none", "gemini", "ollama", "hybrid"
	GeminiBaseURL string
	GeminiAPIKey  string
	GeminiModel   string
	GeminiTimeout time.Duration
	OllamaBaseURL string
	OllamaModel   string
	OllamaTimeout time.Duration
}

// Client acts as the unified AI refinement manager. It implements the Provider interface.
type Client struct {
	mu           sync.RWMutex
	providerType string
	gemini       *GeminiClient
	ollama       *OllamaClient
}

// GeminiClient implements Provider for Google Gemini API.
type GeminiClient struct {
	mu      sync.RWMutex
	baseURL string
	apiKey  string
	model   string
	timeout time.Duration
	http    *http.Client
}

type Result struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Category   string  `json:"category"`
}

type generateRequest struct {
	Contents []content        `json:"contents"`
	Config   generationConfig `json:"generationConfig"`
}

type generationConfig struct {
	Temperature      float64 `json:"temperature,omitempty"`
	ResponseMimeType string  `json:"responseMimeType,omitempty"`
}

type content struct {
	Role  string `json:"role,omitempty"`
	Parts []part `json:"parts"`
}

type part struct {
	Text string `json:"text"`
}

type generateResponse struct {
	Candidates []struct {
		Content struct {
			Parts []part `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// NewClient initializes the AI Client manager with the selected provider type.
func NewClient(cfg Config) *Client {
	prov := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if prov == "" {
		if cfg.GeminiAPIKey != "" {
			prov = "gemini"
		} else {
			prov = "none"
		}
	}

	c := &Client{
		providerType: prov,
	}

	if prov == "gemini" || prov == "hybrid" {
		c.gemini = NewGeminiClient(cfg.GeminiBaseURL, cfg.GeminiAPIKey, cfg.GeminiModel, cfg.GeminiTimeout)
	}
	if prov == "ollama" || prov == "hybrid" {
		c.ollama = NewOllamaClient(cfg.OllamaBaseURL, cfg.OllamaModel, cfg.OllamaTimeout)
	}

	return c
}

// New is a legacy constructor kept to maintain 100% backwards-compatibility with existing tests.
func New(baseURL, apiKey, model string, timeout time.Duration) *Client {
	prov := "gemini"
	if apiKey == "" {
		prov = "none"
	}
	return &Client{
		providerType: prov,
		gemini:       NewGeminiClient(baseURL, apiKey, model, timeout),
	}
}

// Enabled returns true if the configured AI provider is enabled and active.
func (c *Client) Enabled() bool {
	if c == nil {
		return false
	}
	providerType, gemini, ollama := c.providers()
	switch providerType {
	case "gemini":
		return gemini != nil && gemini.Enabled()
	case "ollama":
		return ollama != nil && ollama.Enabled()
	case "hybrid":
		return (ollama != nil && ollama.Enabled()) || (gemini != nil && gemini.Enabled())
	default:
		return false
	}
}

func (c *Client) providers() (string, *GeminiClient, *OllamaClient) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.providerType, c.gemini, c.ollama
}

// Refine routes refinement requests to the chosen provider, supporting automatic fallback in hybrid mode.
func (c *Client) Refine(ctx context.Context, domain string, current analysis.Result) (analysis.Result, error) {
	if c == nil {
		return analysis.Result{}, errors.New("ai client disabled")
	}

	providerType, gemini, ollama := c.providers()
	switch providerType {
	case "gemini":
		if gemini != nil && gemini.Enabled() {
			return gemini.Refine(ctx, domain, current)
		}
	case "ollama":
		if ollama != nil && ollama.Enabled() {
			return ollama.Refine(ctx, domain, current)
		}
	case "hybrid":
		// Try local Ollama first
		if ollama != nil && ollama.Enabled() {
			res, err := ollama.Refine(ctx, domain, current)
			if err == nil {
				return res, nil
			}
			logjson.Warn("local ollama refinement failed; falling back to gemini", correlation.Fields(ctx, map[string]any{
				"service": "ai",
				"domain":  domain,
				"error":   err.Error(),
			}))
		}
		// Fallback to Gemini
		if gemini != nil && gemini.Enabled() {
			return gemini.Refine(ctx, domain, current)
		}
		return analysis.Result{}, errors.New("no enabled AI providers in hybrid mode")
	default:
		return analysis.Result{}, errors.New("unknown AI provider type")
	}
	return analysis.Result{}, errors.New("ai client disabled")
}

// NewGeminiClient creates a new client for Google's Gemini API.
func NewGeminiClient(baseURL, apiKey, model string, timeout time.Duration) *GeminiClient {
	baseURL = strings.TrimSpace(baseURL)
	apiKey = strings.TrimSpace(apiKey)
	if model == "" {
		model = defaultModel
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	if apiKey == "" {
		return &GeminiClient{model: model, timeout: timeout}
	}

	return &GeminiClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
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

// Enabled implements Provider for Gemini.
func (g *GeminiClient) Enabled() bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.apiKey != "" && g.http != nil
}

// Refine implements Provider for Gemini.
func (g *GeminiClient) Refine(ctx context.Context, domain string, current analysis.Result) (analysis.Result, error) {
	if !g.Enabled() {
		return analysis.Result{}, errors.New("gemini provider disabled")
	}

	prompt := buildPrompt(domain, current)
	text, err := g.generateText(ctx, prompt)
	if err != nil {
		return analysis.Result{}, err
	}

	var parsed Result
	if err := json.Unmarshal([]byte(extractJSON(text)), &parsed); err != nil {
		return analysis.Result{}, err
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
		result.Reasons = []string{"local ai classification: " + parsed.Reason}
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

func (g *GeminiClient) generateText(ctx context.Context, prompt string) (string, error) {
	baseURL, apiKey, model, timeout, httpClient, enabled := g.requestConfig()
	if !enabled {
		return "", errors.New("gemini provider disabled")
	}

	reqBody, err := json.Marshal(generateRequest{
		Contents: []content{{
			Role:  "user",
			Parts: []part{{Text: prompt}},
		}},
		Config: generationConfig{
			Temperature:      0,
			ResponseMimeType: "application/json",
		},
	})
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	requestURL := fmt.Sprintf("%s/models/%s:generateContent?key=%s", baseURL, url.PathEscape(model), url.QueryEscape(apiKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("gemini returned HTTP %d", resp.StatusCode)
	}

	var envelope generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return "", err
	}
	if envelope.Error.Message != "" {
		return "", errors.New(envelope.Error.Message)
	}

	return firstResponseText(envelope)
}

func (g *GeminiClient) requestConfig() (string, string, string, time.Duration, *http.Client, bool) {
	if g == nil {
		return "", "", "", 0, nil, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.baseURL, g.apiKey, g.model, g.timeout, g.http, g.apiKey != "" && g.http != nil
}

func (g *GeminiClient) setAPIKey(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.apiKey = key
	if g.http == nil && key != "" {
		g.http = &http.Client{
			Timeout: g.timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
	}
}

func firstResponseText(envelope generateResponse) (string, error) {
	if len(envelope.Candidates) == 0 {
		return "", errors.New("gemini returned no candidates")
	}
	parts := envelope.Candidates[0].Content.Parts
	if len(parts) == 0 {
		return "", errors.New("gemini returned no content parts")
	}

	var builder strings.Builder
	for _, item := range parts {
		builder.WriteString(item.Text)
	}

	return strings.TrimSpace(builder.String()), nil
}

func extractJSON(text string) string {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "{") && strings.HasSuffix(text, "}") {
		return text
	}

	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		return text[start : end+1]
	}

	return text
}

func buildPrompt(domain string, current analysis.Result) string {
	return fmt.Sprintf(`Bạn là chuyên gia bảo mật. Phân tích domain sau: %s
Kết quả hiện tại: verdict=%s, score=%d, confidence=%.2f

Trả lời CHÍNH XÁC theo JSON:
{"verdict": "SAFE|SUSPICIOUS|MALICIOUS", "confidence": 0.0-1.0, "category": "social_media|adult|gambling|gaming|advertising|malware|phishing|uncategorized", "reason": "giải thích ngắn"}`,
		domain, current.Verdict, current.Score, current.Confidence)
}

// SetGeminiAPIKey dynamically updates the Gemini API key used by the client.
func (c *Client) SetGeminiAPIKey(key string) {
	if c == nil {
		return
	}
	key = strings.TrimSpace(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gemini == nil {
		c.gemini = NewGeminiClient("", key, "", 3*time.Second)
	} else {
		c.gemini.setAPIKey(key)
	}
	if c.providerType == "none" || c.providerType == "" {
		c.providerType = "gemini"
	}
}
