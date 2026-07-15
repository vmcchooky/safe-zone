package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/api/views"
	"strings"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/serve"
)

type blockPageData struct {
	Domain          string
	RequestedPath   string
	Category        string
	Reason          string
	SupportEmail    string
	ReportReceived  bool
	RequestID       string
	HTTPSLimitation bool
}

func (h *Handler) BlockPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	data := blockPageData{
		Domain:          blockedDomainFromRequest(r),
		RequestedPath:   blockedPathFromRequest(r),
		Category:        firstNonEmpty(r.URL.Query().Get("category"), "policy block"),
		Reason:          firstNonEmpty(r.URL.Query().Get("reason"), "This request was redirected because the requested domain matched a Safe Zone block policy."),
		SupportEmail:    strings.TrimSpace(config.String("SAFE_ZONE_BLOCK_PAGE_SUPPORT_EMAIL", "")),
		ReportReceived:  r.URL.Query().Get("reported") == "1",
		RequestID:       serve.RequestID(r.Context()),
		HTTPSLimitation: true,
	}
	if data.Domain == "" {
		data.Domain = "the requested domain"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.ExecuteBlockPage(w, data); err != nil {
		logjson.Error("block page render failed", correlation.Fields(r.Context(), map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		}))
	}
}

func (h *Handler) BlockReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid form body")
		return
	}

	domain := firstNonEmpty(
		strings.TrimSpace(r.Form.Get("domain")),
		blockedDomainFromRequest(r),
	)
	requestedPath := firstNonEmpty(strings.TrimSpace(r.Form.Get("requested_path")), blockedPathFromRequest(r))
	contact := strings.TrimSpace(r.Form.Get("contact"))
	note := strings.TrimSpace(r.Form.Get("note"))
	reportDetails, err := json.Marshal(map[string]string{
		"domain":         domain,
		"requested_path": requestedPath,
		"contact":        contact,
		"note":           note,
		"user_agent":     r.UserAgent(),
		"request_id":     serve.RequestID(r.Context()),
		"reported_at":    time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to serialize report")
		return
	}

	if db := h.Risk.StoreDB(); db != nil && db.Enabled() {
		if _, err := db.CreateBlockReport(r.Context(), domain, contact, note); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "failed to record report")
			return
		}
		if err := db.RecordAgentEvent(r.Context(), "block_page", "false_positive_report", domain, string(reportDetails)); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "failed to record report")
			return
		}
	}

	redirectTarget := "/block?reported=1"
	if domain != "" {
		redirectTarget += "&domain=" + url.QueryEscape(domain)
	}
	if requestedPath != "" {
		redirectTarget += "&path=" + url.QueryEscape(requestedPath)
	}
	http.Redirect(w, r, redirectTarget, http.StatusSeeOther)
}

func blockedDomainFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if value := normalizeBlockPageDomain(r.URL.Query().Get("domain")); value != "" {
		return value
	}
	if value := normalizeBlockPageDomain(r.Header.Get("X-Blocked-Domain")); value != "" {
		return value
	}
	return normalizeBlockPageDomain(r.Host)
}

func blockedPathFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if value := strings.TrimSpace(r.URL.Query().Get("path")); value != "" {
		return value
	}
	if value := strings.TrimSpace(r.Header.Get("X-Original-Path")); value != "" {
		return value
	}
	if r.URL.Path != "" && r.URL.Path != "/block" && r.URL.Path != "/block/report" {
		return r.URL.Path
	}
	return "/"
}

func normalizeBlockPageDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	return strings.TrimSuffix(value, ".")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
