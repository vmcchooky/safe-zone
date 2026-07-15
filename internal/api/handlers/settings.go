package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/config"
	"safe-zone/internal/netguard"
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

		if req.GeminiAPIKey != "" {
			if !strings.Contains(req.GeminiAPIKey, "*") {
				if err := db.SetSystemConfig(r.Context(), "gemini_api_key", strings.TrimSpace(req.GeminiAPIKey)); err != nil {
					httputil.WriteError(w, http.StatusInternalServerError, "failed to save gemini_api_key: "+err.Error())
					return
				}
				if h.Risk != nil {
					h.Risk.AIClient()
				}
			}
		} else {
			if err := db.SetSystemConfig(r.Context(), "gemini_api_key", ""); err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, "failed to clear gemini_api_key: "+err.Error())
				return
			}
		}

		if req.AgentWebhookURL != "" {
			if !strings.Contains(req.AgentWebhookURL, "*") {
				webhookURL := strings.TrimSpace(req.AgentWebhookURL)
				if _, err := netguard.ValidateURL(webhookURL, false); err != nil {
					httputil.WriteError(w, http.StatusBadRequest, "invalid agent_webhook_url: "+err.Error())
					return
				}
				if err := db.SetSystemConfig(r.Context(), "agent_webhook_url", webhookURL); err != nil {
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
