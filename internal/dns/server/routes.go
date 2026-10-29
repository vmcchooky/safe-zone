package server

import (
	"net/http"

	"safe-zone/internal/dns/doh"
	"safe-zone/internal/dns/resolver"
	"safe-zone/internal/serve"
)

// RouteAuth mirrors the middleware NewRouter applies to a route. It is part
// of the registered-route contract the OpenAPI parity test asserts against
// docs/openapi/safe-zone.yaml.
type RouteAuth string

const (
	// AuthPublic routes answer without credentials.
	AuthPublic RouteAuth = "public"
	// AuthBearerAdmin routes require the admin API key as a bearer token and
	// fail closed when the deployment has no key configured (/metrics).
	AuthBearerAdmin RouteAuth = "bearer-admin"
)

// RouteSpec is one route registered by NewRouter; see the core-api twin in
// internal/api/server/routes.go for the full contract.
type RouteSpec struct {
	Path    string
	Methods []string
	Auth    RouteAuth
}

// apiRoutes is the registration table for every route NewRouter serves.
func apiRoutes() []RouteSpec {
	return []RouteSpec{
		{Path: "/", Methods: []string{"GET"}, Auth: AuthPublic},
		{Path: "/healthz", Methods: []string{"GET"}, Auth: AuthPublic},
		// /readyz is a real readiness probe: it checks the dependencies the
		// resolver needs, so a container that is running but cannot resolve
		// anything is reported as not ready instead of healthy.
		{Path: "/readyz", Methods: []string{"GET"}, Auth: AuthPublic},
		{Path: "/v1/version", Methods: []string{"GET"}, Auth: AuthPublic},
		// /metrics publishes the per-endpoint request summary (method, path,
		// status, counts, latency), which lets any caller fingerprint the
		// service surface and read error and throttle rates — reconnaissance
		// for an attack that does not need a password. It is deliberately
		// bearer-gated and fails closed when no admin key is configured.
		{Path: "/metrics", Methods: []string{"GET"}, Auth: AuthBearerAdmin},
		// /v1/policy is deliberately unauthenticated: it is the decision
		// endpoint DoH clients and the block page consult, and answering it
		// requires no privileged capability. It returns one domain's
		// decision, not state.
		{Path: "/v1/policy", Methods: []string{"GET"}, Auth: AuthPublic},
		{Path: "/dns-query", Methods: []string{"GET", "POST"}, Auth: AuthPublic},
	}
}

// apiHandlers maps every path in apiRoutes to its raw (unwrapped) handler.
// NewRouter applies the middleware from the route's Auth label.
func apiHandlers(r *resolver.Resolver, adminAPIKey string, readinessChecks []serve.ReadinessCheck) map[string]http.Handler {
	return map[string]http.Handler{
		"/":           http.HandlerFunc(r.StatusHandler),
		"/healthz":    resolver.HealthHandler("dns-resolver"),
		"/readyz":     serve.ReadinessHandler("dns-resolver", r.Metrics, readinessChecks...),
		"/v1/version": http.HandlerFunc(r.VersionHandler),
		"/metrics":    http.HandlerFunc(r.MetricsHandler),
		"/v1/policy":  http.HandlerFunc(r.PolicyHandler),
		"/dns-query":  doh.NewHandler(r),
	}
}

func applyRouteAuth(adminAPIKey string, auth RouteAuth, handler http.Handler) http.Handler {
	switch auth {
	case AuthPublic:
		return handler
	case AuthBearerAdmin:
		return serve.RequireBearer(adminAPIKey, handler)
	default:
		panic("unknown route auth: " + string(auth))
	}
}

// SpecRoutes returns the registered route table for the OpenAPI parity test.
// It must stay in sync with registerAPIRoutes by construction: both consume
// apiRoutes.
func SpecRoutes() []RouteSpec {
	return apiRoutes()
}

// registerAPIRoutes mounts every entry of apiRoutes. A table path without a
// handler is an invariant violation and fails router construction loudly.
func registerAPIRoutes(mux *http.ServeMux, r *resolver.Resolver, adminAPIKey string, readinessChecks []serve.ReadinessCheck) {
	handlersByPath := apiHandlers(r, adminAPIKey, readinessChecks)
	for _, route := range apiRoutes() {
		handler, ok := handlersByPath[route.Path]
		if !ok {
			panic("route table has no handler for " + route.Path)
		}
		mux.Handle(route.Path, applyRouteAuth(adminAPIKey, route.Auth, handler))
	}
}
