package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
	"safe-zone/internal/risk"
)

type settingsResponse struct {
	GeminiAPIKey           string               `json:"gemini_api_key"`
	AgentWebhookURL        string               `json:"agent_webhook_url"`
	TelemetryRetentionDays int                  `json:"telemetry_retention_days"`
	Adblock                *risk.AdblockControl `json:"adblock"`
	// AdblockSourcePoliciesJSON is the effective per-source policy document
	// as the operator would write it, so the dashboard can round-trip the
	// setting instead of reconstructing it. Empty when the environment is in
	// force and nothing has been persisted.
	AdblockSourcePoliciesJSON string `json:"adblock_source_policies_json"`
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
	// AdblockSourcePoliciesJSON is the per-source policy document. A pointer
	// keeps "omitted" distinct from "empty, fall back to the environment",
	// so saving another setting never clears the policies.
	AdblockSourcePoliciesJSON *string `json:"adblock_source_policies_json"`
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

	adblock := h.Risk.Adblock().AdblockControl()
	// Read the persisted value, not the in-memory one: the operator is editing
	// a document, and on a second process the persisted copy is what this one
	// is reconciling against every 30 seconds.
	//
	// A read failure here is deliberately non-fatal. The refresher
	// (risk.refreshAdblockSourcePolicies) treats the same key fail-soft and
	// keeps the policy in force; if this read instead failed the whole request,
	// one transient store error would take down the entire settings page —
	// Gemini key, webhook, retention, the adblock switch, guest access — for
	// a field the operator was not even asking about. Returning empty lets the
	// editor show what is unreadable rather than blanking the page.
	sourcePolicies, err := db.GetSystemConfig(ctx, risk.SystemConfigAdblockSourcePolicies)
	if err != nil {
		logjson.Warn("could not read the persisted adblock source policies; showing them as empty", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
		sourcePolicies = ""
	}
	return settingsResponse{
		GeminiAPIKey:              maskConfigValue(apiKey),
		AgentWebhookURL:           maskConfigValue(webhookURL),
		TelemetryRetentionDays:    db.GetRetentionDays(ctx),
		Adblock:                   &adblock,
		AdblockSourcePoliciesJSON: sourcePolicies,
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
			httputil.WriteStoreError(w, r, err, "database not available")
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

		// Validate the whole document before touching anything.
		//
		// The handler used to apply field by field, so a request carrying two
		// changes could persist the first and then reject the second with a 400 —
		// leaving the operator believing nothing was saved. The webhook URL was
		// validated only after the Gemini key had already been written, which
		// meant the same thing for the most security-relevant pair of fields in
		// this handler.
		//
		// Two kinds of "skip" are also reported now instead of returning 200 for
		// a change that was never applied: a masked value (the GET response
		// returns "abcd****", which is what the `*` check detects) and a
		// non-positive retention. Silently ignoring either leaves the operator
		// with a settings screen that disagrees with the server.
		steps, err := req.validate(r.Context(), db, h.Risk)
		if err != nil {
			var invalid *settingsValidationError
			if errors.As(err, &invalid) {
				httputil.WriteError(w, http.StatusBadRequest, invalid.Error())
				return
			}
			if errors.Is(err, risk.ErrAdblockSourcePoliciesInvalid) {
				httputil.WriteError(w, http.StatusBadRequest, err.Error())
				return
			}
			httputil.WriteStoreError(w, r, err, "failed to apply settings")
			return
		}
		if len(steps) == 0 {
			httputil.WriteError(w, http.StatusBadRequest, "no recognised setting in the request")
			return
		}
		if err := applySettings(steps); err != nil {
			httputil.WriteStoreError(w, r, err, "failed to apply settings")
			return
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

	// This bundles settings with analysis config and guest access, and the UI
	// fetches it on load, so a disabled store has to be a 503 like every other
	// settings path rather than a 500. Without this guard the store reads below
	// returned errors that reached the client as err.Error().
	if db := h.Risk.StoreDB(); db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "database not configured")
		return
	}

	settings, err := h.loadSettingsResponse(r.Context())
	if err != nil {
		httputil.WriteStoreError(w, r, err, "database not available")
		return
	}
	guestCfg, err := h.loadGuestAccessConfig(r.Context())
	if err != nil {
		httputil.WriteStoreError(w, r, err, "database not available")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, settingsBundleResponse{
		Settings:       settings,
		AnalysisConfig: h.Risk.GetAnalysisConfig(),
		GuestAccess:    guestAccessStatus(guestCfg),
	})
}
