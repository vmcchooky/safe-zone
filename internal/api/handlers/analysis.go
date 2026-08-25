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
}

func (h *Handler) AnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	var domain string
	var urlContext *risk.URLAnalysisContext

	switch r.Method {
	case http.MethodGet:
		domain = r.URL.Query().Get("domain")
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		defer func() { _ = r.Body.Close() }()
		var req analyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		domain = req.Domain
		if req.RequestedURL != "" || len(req.RedirectChain) > 0 {
			urlContext = &risk.URLAnalysisContext{
				RequestedURL:  req.RequestedURL,
				RedirectChain: append([]string(nil), req.RedirectChain...),
			}
		}
	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clientInfo := httputil.ExtractClientInfo(r)
	response := h.Risk.AnalyzeWithOptions(r.Context(), domain, clientInfo, risk.AnalyzeOptions{
		IncludeEvidence: r.URL.Query().Get("include_evidence") == "1",
		ForceOSINT:      r.URL.Query().Get("force_osint") == "1",
		URLContext:      urlContext,
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
	result := h.Risk.InspectRawData(r.Context(), domain)
	httputil.WriteJSON(w, http.StatusOK, result)
}
