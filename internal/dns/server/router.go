package server

import (
	"net/http"

	"safe-zone/internal/dns/doh"
	"safe-zone/internal/dns/resolver"
	"safe-zone/internal/ratelimit"
)

func NewRouter(r *resolver.Resolver, tiered *ratelimit.TieredMiddleware) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.StatusHandler)
	mux.HandleFunc("/healthz", resolver.HealthHandler("dns-resolver"))
	mux.HandleFunc("/v1/version", r.VersionHandler)
	mux.HandleFunc("/metrics", r.MetricsHandler)
	mux.HandleFunc("/v1/policy", r.PolicyHandler)
	mux.Handle("/dns-query", doh.NewHandler(r))
	mux.Handle("/dns-query/", doh.NewHandler(r))

	return mux
}
