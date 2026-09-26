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
	"safe-zone/internal/risk"
)

type settingsResponse struct {
	GeminiAPIKey           string               `json:"gemini_api_key"`
	AgentWebhookURL        string               `json:"agent_webhook_url"`
	TelemetryRetentionDays int                  `json:"telemetry_retention_days"`
	Adblock                *risk.AdblockControl `json:"adblock"`
}

type settingsRequest struct {
	// Pointers distinguish an omitted field from an intentionally empty value.
	// This lets the Gemini and webhook settings be saved independently.
	GeminiAPIKey           *string `json:"gemini_api_key"`
	AgentWebhookURL        *string `json:"agent_webhook_url"`
	TelemetryRetentionDays *int    `json:"telemetry_retention_days"`
	// AdblockEnabled toggles adblock. A pointer keeps "field omitted" distinct
	// from "explicitly false", so saving another setting never silently turns
	// the adblock layer off.
	AdblockEnabled *bool `json:"adblock_enabled"`
	// AdblockMatchMode selects rule scope: "suffix" or "exact".
	AdblockMatchMode *string `json:"adblock_match_mode"`
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

	adblock := h.Risk.AdblockControl()
	return settingsResponse{
		GeminiAPIKey:           maskConfigValue(apiKey),
		AgentWebhookURL:        maskConfigValue(webhookURL),
		TelemetryRetentionDays: db.GetRetentionDays(ctx),
		Adblock:                &adblock,
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
		defer func() { _ = r.Body.Close() }()
		var req settingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		if req.GeminiAPIKey != nil {
			apiKey := strings.TrimSpace(*req.GeminiAPIKey)
			if apiKey != "" {
				if !strings.Contains(apiKey, "*") {
					if err := db.SetSystemConfig(r.Context(), "gemini_api_key", apiKey); err != nil {
						httputil.WriteError(w, http.StatusInternalServerError, "failed to save gemini_api_key: "+err.Error())
						return
					}
				}
			} else {
				if err := db.SetSystemConfig(r.Context(), "gemini_api_key", ""); err != nil {
					httputil.WriteError(w, http.StatusInternalServerError, "failed to clear gemini_api_key: "+err.Error())
					return
				}
			}
		}

		if req.AgentWebhookURL != nil {
			webhookURL := strings.TrimSpace(*req.AgentWebhookURL)
			if webhookURL != "" {
				if !strings.Contains(webhookURL, "*") {
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
		}

		if req.TelemetryRetentionDays != nil && *req.TelemetryRetentionDays > 0 {
			db.UpdateRetentionDays(r.Context(), *req.TelemetryRetentionDays)
			if err := db.SetSystemConfig(r.Context(), "telemetry_retention_days", strconv.Itoa(*req.TelemetryRetentionDays)); err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, "failed to save telemetry_retention_days: "+err.Error())
				return
			}
		}

		// Adblock switches. Order matters: the mode is validated before it is
		// applied so an unsupported value cannot leave the layer half-changed,
		// and enabling is applied last so a request that fails validation
		// changes nothing at all.
		if req.AdblockMatchMode != nil {
			if err := h.Risk.SetAdblockMatchMode(r.Context(), *req.AdblockMatchMode); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, "invalid adblock_match_mode: "+err.Error())
				return
			}
		}
		if req.AdblockEnabled != nil {
			if err := h.Risk.SetAdblockEnabled(r.Context(), *req.AdblockEnabled); err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, "failed to save adblock_enabled: "+err.Error())
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
