package server

import (
	"net/http"

	"safe-zone/internal/dns/doh"
	"safe-zone/internal/dns/resolver"
	"safe-zone/internal/serve"
)

// NewRouter builds the DNS service HTTP mux. Rate limiting is NOT applied
// here: the caller wraps the returned mux exactly once with
// TieredMiddleware.Wrap so DoH and policy endpoints share one limiter.
//
// adminAPIKey gates /metrics. That endpoint publishes the per-endpoint request
// summary (method, path, status, counts, latency), which lets any caller
// fingerprint the service surface and read error and throttle rates. core-api
// gates its own /metrics for the same reason; dns-resolver had been left open
// on the argument that it has no accounts and therefore no login endpoint to
// brute-force. That argument does not hold: the request summary still reveals
// which endpoints exist, how they are used, and when the resolver is under
// load, which is reconnaissance for an attack that does not need a password.
//
// An empty adminAPIKey denies /metrics rather than exposing it. The caller
// logs that state at startup so a missing key is diagnosed instead of
// silently turning the endpoint into a 401 for the monitoring stack.
func NewRouter(r *resolver.Resolver, adminAPIKey string) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", r.StatusHandler)
	mux.HandleFunc("/healthz", resolver.HealthHandler("dns-resolver"))
	mux.HandleFunc("/v1/version", r.VersionHandler)
	mux.Handle("/metrics", serve.RequireBearer(adminAPIKey, http.HandlerFunc(r.MetricsHandler)))
	// /v1/policy is deliberately unauthenticated: it is the decision endpoint
	// DoH clients and the block page consult, and answering it requires no
	// privileged capability. It returns one domain's decision, not state.
	mux.HandleFunc("/v1/policy", r.PolicyHandler)
	mux.Handle("/dns-query", doh.NewHandler(r))
	mux.Handle("/dns-query/", doh.NewHandler(r))

	return mux
}
