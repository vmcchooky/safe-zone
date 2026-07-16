package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/config"
	"safe-zone/internal/netguard"
)

type testAlertEvent struct {
	Type      string `json:"type"`
	Domain    string `json:"domain,omitempty"`
	Details   string `json:"details,omitempty"`
	CreatedAt string `json:"created_at"`
}

type testAlertPayload struct {
	Timestamp string           `json:"timestamp"`
	EventType string           `json:"event_type"`
	Summary   string           `json:"summary"`
	Events    []testAlertEvent `json:"events"`
}

type testAIRequest struct {
	GeminiAPIKey string `json:"gemini_api_key"`
}

type testAlertRequest struct {
	AgentWebhookURL string `json:"agent_webhook_url"`
}

func decodeOptionalTestRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(target); err != nil && !errors.Is(err, io.EOF) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func (h *Handler) geminiKeyForTest(ctx context.Context, submitted string) string {
	key := strings.TrimSpace(submitted)
	if key != "" && !strings.Contains(key, "*") {
		return key
	}

	if h != nil && h.Risk != nil {
		if db := h.Risk.StoreDB(); db != nil && db.Enabled() {
			if saved, err := db.GetSystemConfig(ctx, "gemini_api_key"); err == nil && strings.TrimSpace(saved) != "" {
				return strings.TrimSpace(saved)
			}
		}
	}
	return config.SecretString("SAFE_ZONE_GEMINI_API_KEY", "")
}

func (h *Handler) webhookURLForTest(ctx context.Context, submitted string) string {
	webhookURL := strings.TrimSpace(submitted)
	if webhookURL != "" && !strings.Contains(webhookURL, "*") {
		return webhookURL
	}

	if h != nil && h.Risk != nil {
		if db := h.Risk.StoreDB(); db != nil && db.Enabled() {
			if saved, err := db.GetSystemConfig(ctx, "agent_webhook_url"); err == nil && strings.TrimSpace(saved) != "" {
				return strings.TrimSpace(saved)
			}
		}
	}
	return config.SecretString("SAFE_ZONE_AGENT_WEBHOOK_URL", "")
}

func (h *Handler) TestAIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req testAIRequest
	if !decodeOptionalTestRequest(w, r, &req) {
		return
	}

	apiKey := h.geminiKeyForTest(r.Context(), req.GeminiAPIKey)
	if apiKey == "" {
		httputil.WriteError(w, http.StatusBadRequest, "Gemini API key is not configured")
		return
	}
	aiClient := ai.NewClient(ai.Config{
		Provider:      "gemini",
		GeminiBaseURL: config.String("SAFE_ZONE_GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"),
		GeminiAPIKey:  apiKey,
		GeminiModel:   config.String("SAFE_ZONE_GEMINI_MODEL", "gemini-2.5-flash-lite"),
		GeminiTimeout: config.DurationMillis("SAFE_ZONE_GEMINI_TIMEOUT_MS", 3*time.Second),
	})

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	testRes := analysis.Result{
		Domain:     "test-api-key.com",
		Verdict:    analysis.VerdictSuspicious,
		Score:      50,
		Confidence: 0.5,
		Reasons:    []string{"testing API key configuration"},
	}

	res, err := aiClient.Refine(ctx, "test-api-key.com", testRes)
	if err != nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"verdict": res.Verdict,
		"reason":  strings.Join(res.Reasons, "; "),
	})
}

func (h *Handler) TestAlertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var testReq testAlertRequest
	if !decodeOptionalTestRequest(w, r, &testReq) {
		return
	}

	webhookURL := h.webhookURLForTest(r.Context(), testReq.AgentWebhookURL)
	if webhookURL == "" {
		httputil.WriteError(w, http.StatusBadRequest, "No webhook URL configured")
		return
	}
	if _, err := netguard.ValidateURL(webhookURL, false); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid agent_webhook_url: "+err.Error())
		return
	}

	payload := testAlertPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "safe_zone_test_alert",
		Summary:   "Safe Zone: This is a test notification from the management console",
		Events: []testAlertEvent{
			{
				Type:      "test_alert",
				Domain:    "test-notification.com",
				Details:   "Testing Discord/Slack Alert Channel Configuration",
				CreatedAt: time.Now().Format(time.RFC3339),
			},
		},
	}

	var body []byte
	var err error
	if strings.Contains(webhookURL, "discord.com/api/webhooks") || strings.Contains(webhookURL, "discordapp.com/api/webhooks") {
		discord := map[string]any{
			"embeds": []map[string]any{
				{
					"title":       "🔔 Safe Zone Test Alert",
					"description": "🟢 Your Alert Notification integration is working perfectly!",
					"color":       3066993,
					"footer": map[string]string{
						"text": payload.Summary,
					},
					"timestamp": payload.Timestamp,
				},
			},
		}
		body, err = json.Marshal(discord)
	} else {
		body, err = json.Marshal(payload)
	}

	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to marshal payload: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to create request: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := netguard.NewHTTPClient(nil, 10*time.Second, false).Do(req)
	if err != nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "error",
			"error":  fmt.Sprintf("Webhook returned status %d", resp.StatusCode),
		})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
	})
}
