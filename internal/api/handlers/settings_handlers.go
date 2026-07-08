package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/config"
)

type settingsResponse struct {
	GeminiAPIKey           string `json:"gemini_api_key"`
	AgentWebhookURL        string `json:"agent_webhook_url"`
	TelemetryRetentionDays int    `json:"telemetry_retention_days"`
}

type settingsRequest struct {
	GeminiAPIKey           string `json:"gemini_api_key"`
	AgentWebhookURL        string `json:"agent_webhook_url"`
	TelemetryRetentionDays int    `json:"telemetry_retention_days"`
}

type settingsBundleResponse struct {
	Settings       settingsResponse          `json:"settings"`
	AnalysisConfig config.AnalysisConfig     `json:"analysis_config"`
	GuestAccess    guestAccessStatusResponse `json:"guest_access"`
}

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

func maskConfigValue(val string) string {
	if val == "" {
		return ""
	}
	if len(val) <= 4 {
		return strings.Repeat("*", len(val))
	}
	return val[:4] + strings.Repeat("*", len(val)-4)
}

func (h *Handler) loadSettingsResponse(ctx context.Context) (settingsResponse, error) {
	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		return settingsResponse{}, fmt.Errorf("database not configured")
	}

	apiKey, err := db.GetSystemConfig(ctx, "gemini_api_key")
	if err != nil {
		return settingsResponse{}, fmt.Errorf("failed to get gemini_api_key: %w", err)
	}
	webhookURL, err := db.GetSystemConfig(ctx, "agent_webhook_url")
	if err != nil {
		return settingsResponse{}, fmt.Errorf("failed to get agent_webhook_url: %w", err)
	}

	return settingsResponse{
		GeminiAPIKey:           maskConfigValue(apiKey),
		AgentWebhookURL:        maskConfigValue(webhookURL),
		TelemetryRetentionDays: db.GetRetentionDays(ctx),
	}, nil
}

func (h *Handler) SettingsHandler(w http.ResponseWriter, r *http.Request) {
	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		resp, err := h.loadSettingsResponse(r.Context())
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var req settingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Save Gemini API Key if not masked
		if req.GeminiAPIKey != "" {
			if !strings.Contains(req.GeminiAPIKey, "*") {
				if err := db.SetSystemConfig(r.Context(), "gemini_api_key", strings.TrimSpace(req.GeminiAPIKey)); err != nil {
					httputil.WriteError(w, http.StatusInternalServerError, "failed to save gemini_api_key: "+err.Error())
					return
				}
				// Hot reload key in client
				if h.Risk != nil {
					h.Risk.AIClient() // triggers syncAIClient
				}
			}
		} else {
			if err := db.SetSystemConfig(r.Context(), "gemini_api_key", ""); err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, "failed to clear gemini_api_key: "+err.Error())
				return
			}
		}

		// Save Webhook URL if not masked
		if req.AgentWebhookURL != "" {
			if !strings.Contains(req.AgentWebhookURL, "*") {
				if err := db.SetSystemConfig(r.Context(), "agent_webhook_url", strings.TrimSpace(req.AgentWebhookURL)); err != nil {
					httputil.WriteError(w, http.StatusInternalServerError, "failed to save agent_webhook_url: "+err.Error())
					return
				}
			}
		} else {
			if err := db.SetSystemConfig(r.Context(), "agent_webhook_url", ""); err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, "failed to clear agent_webhook_url: "+err.Error())
				return
			}
		}

		// Save Telemetry Retention Days if provided
		if req.TelemetryRetentionDays > 0 {
			db.UpdateRetentionDays(r.Context(), req.TelemetryRetentionDays)
			if err := db.SetSystemConfig(r.Context(), "telemetry_retention_days", strconv.Itoa(req.TelemetryRetentionDays)); err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, "failed to save telemetry_retention_days: "+err.Error())
				return
			}
		}

		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) SettingsBundleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	settings, err := h.loadSettingsResponse(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	guestCfg, err := h.loadGuestAccessConfig(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, settingsBundleResponse{
		Settings:       settings,
		AnalysisConfig: h.Risk.GetAnalysisConfig(),
		GuestAccess:    guestAccessStatus(guestCfg),
	})
}

func (h *Handler) AnalysisConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		httputil.WriteJSON(w, http.StatusOK, h.Risk.GetAnalysisConfig())
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		defer r.Body.Close()
		cfg := h.Risk.GetAnalysisConfig()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid analysis config JSON: "+err.Error())
			return
		}
		if err := h.Risk.UpdateAnalysisConfig(r.Context(), cfg); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, h.Risk.GetAnalysisConfig())
	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) AnalysisConfigResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cfg, err := h.Risk.ResetAnalysisConfig(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httputil.WriteJSON(w, http.StatusOK, cfg)
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
