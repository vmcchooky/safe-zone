package handlers

import (
	"encoding/json"
	"net/http"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/risk"
)

type analyzeRequest struct {
	Domain        string   `json:"domain"`
	RequestedURL  string   `json:"requested_url,omitempty"`
	RedirectChain []string `json:"redirect_chain,omitempty"`
	// EventID is an opaque caller-generated correlation ID used for
	// privacy-safe label feedback. The server never persists it in the clear.
	EventID string `json:"event_id,omitempty"`
	// CallerClass is a coarse non-identifying integration category
	// (ui|sdk|extension|proxy|other) used only for aggregate coverage.
	CallerClass string `json:"caller_class,omitempty"`
}

// Admission bounds for analyze inputs (PR-02/H4, OWASP Input Validation +
// API4:2023 max-size-on-all-params). The domain bound admits pasted URLs
// (scheme/host/path) while rejecting megabyte query strings before any
// analysis work; NormalizeDomain still enforces RFC 1035 wire bounds
// (253/63) downstream. URL-context bounds sit strictly above the URL
// bundle product caps (MaximumRedirects 5, MaximumURLBytes 4096), so the
// bundle keeps enforcing its contract — the handler only bounds copy and
// telemetry memory for pathological callers.
const (
	maxDomainParamChars = 4096
	maxURLContextBytes  = 8192
	maxRedirectChainLen = 16
)

// admitDomainParam rejects oversized domain inputs at the HTTP boundary.
func admitDomainParam(domain string) string {
	if len([]byte(domain)) > maxDomainParamChars {
		return "domain parameter too long"
	}
	return ""
}

// admitURLContext bounds caller-supplied URL evidence before it is copied
// into the analysis request.
func admitURLContext(requestedURL string, chain []string) string {
	if len([]byte(requestedURL)) > maxURLContextBytes {
		return "requested_url too long"
	}
	if len(chain) > maxRedirectChainLen {
		return "redirect_chain too long"
	}
	for _, entry := range chain {
		if len([]byte(entry)) > maxURLContextBytes {
			return "redirect_chain entry too long"
		}
	}
	return ""
}

func (h *Handler) AnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	var domain string
	var urlContext *risk.URLAnalysisContext
	// Structural reason for missing URL context; feeds fixed-bucket aggregate
	// coverage telemetry only and never stores caller data.
	missingContextReason := ""

	switch r.Method {
	case http.MethodGet:
		domain = r.URL.Query().Get("domain")
		if msg := admitDomainParam(domain); msg != "" {
			httputil.WriteError(w, http.StatusBadRequest, msg)
			return
		}
		missingContextReason = "get_domain_only"
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		defer func() { _ = r.Body.Close() }()
		var req analyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if msg := admitDomainParam(req.Domain); msg != "" {
			httputil.WriteError(w, http.StatusBadRequest, msg)
			return
		}
		if msg := admitURLContext(req.RequestedURL, req.RedirectChain); msg != "" {
			httputil.WriteError(w, http.StatusBadRequest, msg)
			return
		}
		domain = req.Domain
		if req.RequestedURL != "" || len(req.RedirectChain) > 0 {
			urlContext = &risk.URLAnalysisContext{
				RequestedURL:  req.RequestedURL,
				RedirectChain: append([]string(nil), req.RedirectChain...),
				EventID:       req.EventID,
				CallerClass:   req.CallerClass,
			}
		} else {
			missingContextReason = "post_not_provided"
		}
	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clientInfo := httputil.ExtractClientInfo(r)
	response := h.Risk.AnalyzeWithOptions(r.Context(), domain, clientInfo, risk.AnalyzeOptions{
		IncludeEvidence:      r.URL.Query().Get("include_evidence") == "1",
		ForceOSINT:           r.URL.Query().Get("force_osint") == "1",
		URLContext:           urlContext,
		MissingContextReason: missingContextReason,
	})
	h.Risk.RecordRecent(r.Context(), response)
	httputil.WriteJSON(w, http.StatusOK, response)
}

func (h *Handler) OsintEvidenceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		httputil.WriteError(w, http.StatusBadRequest, "domain query parameter is required")
		return
	}
	force := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("force") == "1"
	report, err := h.Risk.OSINTEvidence(r.Context(), domain, force)
	if err != nil {
		httputil.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	httputil.WriteJSON(w, http.StatusOK, report)
}

func (h *Handler) RecentAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"items": h.Risk.Recent(r.Context()),
	})
}

func (h *Handler) RawDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		httputil.WriteError(w, http.StatusBadRequest, "domain query parameter is required")
		return
	}
	if msg := admitDomainParam(domain); msg != "" {
		httputil.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	result := h.Risk.InspectRawData(r.Context(), domain)
	httputil.WriteJSON(w, http.StatusOK, result)
}
