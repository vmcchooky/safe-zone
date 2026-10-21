package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"safe-zone/internal/logjson"
	"safe-zone/internal/observability"
)

// ReadinessReport is the outcome of a readiness check.
//
// Status is one of:
//
//	"ok"         every dependency answered
//	"degraded"   an optional dependency failed; the service still answers,
//	             with reduced capability
//	"not_ready"  a mandatory dependency failed; the service cannot work
//
// The per-check values are deliberately coarse ("ok" or "unavailable"). The
// raw error stays in the process log: /readyz is public on both services, and
// a dependency error can name an internal path, host or credential.
type ReadinessReport struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`

	failures map[string]readinessFailure
}

type readinessFailure struct {
	err       error
	mandatory bool
}

// ReadinessCheck is one dependency a service needs to answer correctly.
type ReadinessCheck struct {
	// Name identifies the dependency in the report.
	Name string
	// Mandatory failures make the service not ready. Optional failures only
	// degrade it.
	//
	// The split matters: a Redis outage takes the threat feed and the
	// result cache away, but the resolver still answers DNS queries with the
	// layers that do not need Redis. Reporting that as "not ready" would
	// make an orchestrator restart a service that is working.
	Mandatory bool
	// Check returns nil when the dependency is healthy.
	Check func(ctx context.Context) error
}

// ReadinessTimeout bounds a single dependency check. A readiness probe that
// hangs is worse than one that fails: the orchestrator waits for it.
const ReadinessTimeout = 2 * time.Second

// ReadinessHandler answers a readiness probe.
//
// This is deliberately different from a liveness probe. A liveness probe
// answers "is the process running", which a process with a dead database, a
// wedged agent or an unreadable store still is. A readiness probe answers
// "can this service do its job", which is what an orchestrator needs before
// it routes traffic here, and what a monitoring rule needs before it claims
// the service is up.
//
// HTTP status follows the same split:
//
//	ok        200
//	degraded  200  the service still answers, with reduced capability
//	not_ready 503
//
// A degraded service is intentionally not a 503: an optional dependency
// outage must not make an orchestrator stop routing traffic to a service that
// can still do its job. Alerts should watch the status field and the
// readiness counters, not only the HTTP code.
func ReadinessHandler(service string, metrics *observability.Registry, checks ...ReadinessCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := EvaluateReadiness(r.Context(), checks...)

		for name, failure := range report.failures {
			// The log is the only place the raw error is kept.
			logjson.Warn("readiness check failed", map[string]any{
				"service":   service,
				"check":     name,
				"mandatory": failure.mandatory,
				"error":     failure.err.Error(),
			})
			metrics.IncCounter(readinessCounterName(name, "failures"))
		}
		for name := range report.Checks {
			if _, failed := report.failures[name]; failed {
				continue
			}
			metrics.IncCounter(readinessCounterName(name, "ok"))
		}

		status := http.StatusOK
		if report.Status == "not_ready" {
			status = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)

		payload := map[string]any{
			"service": service,
			"status":  report.Status,
			"time":    time.Now().UTC().Format(time.RFC3339Nano),
		}
		if len(report.Checks) > 0 {
			payload["checks"] = report.Checks
		}
		// The status code is already written, so a marshalling failure can
		// only leave an empty body. The header says JSON either way.
		_ = json.NewEncoder(w).Encode(payload)
	}
}

// EvaluateReadiness runs the checks and classifies the result.
func EvaluateReadiness(ctx context.Context, checks ...ReadinessCheck) ReadinessReport {
	report := ReadinessReport{Status: "ok"}
	if len(checks) == 0 {
		return report
	}

	report.Checks = make(map[string]string, len(checks))
	report.failures = make(map[string]readinessFailure)
	for _, check := range checks {
		if check.Check == nil {
			continue
		}

		checkCtx, cancel := context.WithTimeout(ctx, ReadinessTimeout)
		err := check.Check(checkCtx)
		cancel()

		if err == nil {
			report.Checks[check.Name] = "ok"
			continue
		}

		report.Checks[check.Name] = "unavailable"
		report.failures[check.Name] = readinessFailure{err: err, mandatory: check.Mandatory}
		if check.Mandatory {
			report.Status = "not_ready"
			return report
		}
		if report.Status == "ok" {
			report.Status = "degraded"
		}
	}

	return report
}

// readinessCounterName turns a check name into a bounded metric name. Check
// names come from code, not from requests, but normalising them keeps the
// counter names stable if a future check carries a separator.
func readinessCounterName(check, outcome string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(check) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := b.String()
	if name == "" {
		name = "unnamed"
	}
	return "readiness_check_" + name + "_" + outcome + "_total"
}
