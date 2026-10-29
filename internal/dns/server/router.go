package server

import (
	"net/http"

	"safe-zone/internal/dns/resolver"
	"safe-zone/internal/serve"
)

// NewRouter builds the DNS service HTTP mux. API routes come from the table
// in routes.go, which is the single source of truth for paths and auth
// wrappers and the contract the OpenAPI parity test asserts against
// docs/openapi/safe-zone.yaml.
//
// Rate limiting is NOT applied here: the caller wraps the returned mux
// exactly once with TieredMiddleware.Wrap so DoH and policy endpoints share
// one limiter.
//
// adminAPIKey gates /metrics. An empty adminAPIKey denies /metrics rather
// than exposing it (see routes.go); the caller logs that state at startup so
// a missing key is diagnosed instead of silently turning the endpoint into a
// 401 for the monitoring stack.
func NewRouter(r *resolver.Resolver, adminAPIKey string, readinessChecks ...serve.ReadinessCheck) *http.ServeMux {
	mux := http.NewServeMux()

	registerAPIRoutes(mux, r, adminAPIKey, readinessChecks)

	return mux
}
