package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/config"
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

func (h *Handler) TestAIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	aiClient := h.Risk.AIClient()
	if aiClient == nil || !aiClient.Enabled() {
		httputil.WriteError(w, http.StatusBadRequest, "AI client is not configured or disabled")
		return
	}

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

	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	webhookURL := ""
	if customURL, err := db.GetSystemConfig(r.Context(), "agent_webhook_url"); err == nil && customURL != "" {
		webhookURL = customURL
	}
	if webhookURL == "" {
		webhookURL = config.SecretString("SAFE_ZONE_AGENT_WEBHOOK_URL", "")
	}

	if webhookURL == "" {
		httputil.WriteError(w, http.StatusBadRequest, "No webhook URL configured")
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

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
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
