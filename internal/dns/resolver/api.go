package resolver

import (
	"net/http"
	"time"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/risk"
)

type policyResponse struct {
	Service string `json:"service"`
	risk.Policy
	Meta map[string]string `json:"meta,omitempty"`
}

func HealthHandler(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"service": service,
			"status":  "ok",
			"time":    time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
}

func (r *Resolver) StatusHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	if req.Method != http.MethodGet {
		httputil.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"service":                "dns-resolver",
		"status":                 "ok",
		"mode":                   "doh",
		"deployment_tier":        r.Config.DeploymentTier,
		"upstream_doh":           r.Upstreams.PrimaryURL(),
		"upstream_doh_resolvers": r.Upstreams.Status(),
		"redis":                  r.Risk.CacheStatus(req.Context()),
		"analysis_config_reload": r.Risk.AnalysisConfigReloadStatus(),
		"endpoints": []string{
			"/",
			"/healthz",
			"/v1/version",
			"/v1/policy?domain=example.com",
			"/dns-query",
		},
		"time": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (r *Resolver) MetricsHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		httputil.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	upstreamFailures := int64(0)
	if r.Metrics != nil {
		upstreamFailures = r.Metrics.Snapshot().Counters["upstream_doh_failures_total"]
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"service":                "dns-resolver",
		"status":                 "ok",
		"metrics":                r.Metrics.Snapshot(),
		"analysis_config_reload": r.Risk.AnalysisConfigReloadStatus(),
		"upstream_doh": map[string]any{
			"failures_total": upstreamFailures,
		},
		"time": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (r *Resolver) VersionHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		httputil.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, buildinfo.Snapshot("dns-resolver", r.Config.DeploymentTier))
}

func (r *Resolver) PolicyHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		httputil.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	domain := req.URL.Query().Get("domain")
	clientInfo := httputil.ExtractClientInfo(req)
	policy := r.Risk.Policy(req.Context(), domain, clientInfo)

	httputil.WriteJSON(w, http.StatusOK, policyResponse{
		Service: "dns-resolver",
		Policy:  policy,
		Meta: map[string]string{
			"mode":         "doh",
			"upstream_doh": r.Upstreams.PrimaryURL(),
		},
	})
}
