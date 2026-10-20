package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// ReadinessReport is the outcome of a readiness check.
//
// Status is one of:
//
//	"ok"         every dependency answered
//	"degraded"   an optional dependency failed; the service still answers,
//	             with reduced capability
//	"not_ready"  a mandatory dependency failed; the service cannot work
type ReadinessReport struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
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
func ReadinessHandler(service string, checks ...ReadinessCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := EvaluateReadiness(r.Context(), checks...)

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

		report.Checks[check.Name] = err.Error()
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
