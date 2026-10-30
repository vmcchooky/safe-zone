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

// StatusResponse is the typed resolver status surface. It used to be an
// untyped map, which meant the alert-rule contract test could not detect a
// renamed or dropped field. The JSON shape is unchanged.
type StatusResponse struct {
	Service              string                          `json:"service"`
	Status               string                          `json:"status"`
	Mode                 string                          `json:"mode"`
	DeploymentTier       string                          `json:"deployment_tier"`
	UpstreamDoH          string                          `json:"upstream_doh"`
	UpstreamDoHResolvers map[string]any                  `json:"upstream_doh_resolvers"`
	DNSCache             ResponseCacheStats              `json:"dns_cache"`
	Redis                risk.CacheStatus                `json:"redis"`
	AnalysisConfigReload risk.AnalysisConfigReloadStatus `json:"analysis_config_reload"`
	Whitelist            risk.WhitelistLoadStatus        `json:"whitelist"`
	ML                   risk.MLStatus                   `json:"ml"`
	Adblock              risk.AdblockStatus              `json:"adblock"`
	DecisionPipeline     risk.DecisionPipelineStatus     `json:"decision_pipeline"`
	Endpoints            []string                        `json:"endpoints"`
	Time                 string                          `json:"time"`
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

	httputil.WriteJSON(w, http.StatusOK, StatusResponse{
		Service:              "dns-resolver",
		Status:               "ok",
		Mode:                 "doh",
		DeploymentTier:       r.Config.DeploymentTier,
		UpstreamDoH:          r.Upstreams.PrimaryURL(),
		UpstreamDoHResolvers: r.Upstreams.Status(),
		DNSCache:             r.Cache.Stats(),
		Redis:                r.Risk.Telemetry().CacheStatus(req.Context()),
		AnalysisConfigReload: r.Risk.AnalysisConfigReloadStatus(),
		// The allow list lives in this process's RAM too. Publishing the
		// revision is how an operator sees that a rollback reached the
		// resolver, instead of inferring it from a DNS answer.
		Whitelist: r.Risk.Whitelist().LoadStatus(),
		ML:        r.Risk.ML().MLStatus(req.Context()),
		// This service holds its own adblock configuration copy, reconciled
		// from the store on the same 30s cycle as core-api. Publishing the
		// fingerprint here is what makes a split configuration detectable
		// instead of something an operator has to infer.
		Adblock:          r.Risk.Adblock().AdblockStatus(),
		DecisionPipeline: r.Risk.DecisionPipelineStatus(),
		Endpoints: []string{
			"/",
			"/healthz",
			"/v1/version",
			"/v1/policy?domain=example.com",
			"/dns-query",
		},
		Time: time.Now().UTC().Format(time.RFC3339Nano),
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
		"redis":                  r.Risk.Telemetry().CacheStatus(req.Context()),
		"analysis_config_reload": r.Risk.AnalysisConfigReloadStatus(),
		"ml":                     r.Risk.ML().MLStatus(req.Context()),
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
