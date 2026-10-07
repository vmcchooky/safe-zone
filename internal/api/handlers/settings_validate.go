package handlers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"safe-zone/internal/netguard"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

// settingsValidationError marks a request the caller must fix. It is distinct
// from a store failure so the handler can answer 400 rather than 503/500, and
// distinct from a skipped field so nothing is silently dropped.
type settingsValidationError struct{ msg string }

func (e *settingsValidationError) Error() string { return e.msg }

func invalidSettings(format string, args ...any) error {
	return &settingsValidationError{msg: fmt.Sprintf(format, args...)}
}

// Retention bounds. There is a floor because zero or negative is a silent
// no-op, and a ceiling because the value goes straight into a DATE
// subtraction: a large enough number produces a cutoff in the year -5473788,
// which SQLite's TEXT comparison against a modern timestamp never matches, so
// pruning would stop deleting anything and the telemetry table would grow
// without bound. That is exactly what SAFE_ZONE_TELEMETRY_WRITE_PERCENT exists
// to prevent.
const (
	minTelemetryRetentionDays = store.MinRetentionDays
	maxTelemetryRetentionDays = store.MaxRetentionDays
)

// settingStep is one validated write, labelled with the field that produced it.
//
// The name exists so the ordering is observable. Adblock enablement has to be
// applied last no matter where the document listed it, and that rule is easy to
// break by moving a block around, so it is asserted against this slice instead of
// left to a comment.
type settingStep struct {
	field string
	apply func() error
}

// validate checks the entire document and returns the ordered apply steps, or
// nil if the request named nothing this handler owns.
//
// The split is the point. Everything that can reject the request happens first,
// so a document with two changes cannot persist the first and then fail the
// second. apply then performs writes that are expected to succeed, and its errors
// are store failures rather than caller mistakes.
func (req settingsRequest) validate(ctx context.Context, db *store.DB, svc *risk.Service) ([]settingStep, error) {
	var steps []settingStep

	if req.GeminiAPIKey != nil {
		apiKey := strings.TrimSpace(*req.GeminiAPIKey)
		switch {
		case apiKey == "":
			steps = append(steps, settingStep{field: "gemini_api_key", apply: func() error {
				return db.SetSystemConfig(ctx, "gemini_api_key", "")
			}})
		case strings.Contains(apiKey, "*"):
			// The GET response masks the stored key as "abcd****...", so a client
			// that echoes it back would store the mask. That was a silent 200 for
			// a change that never happened.
			return nil, invalidSettings("gemini_api_key still contains the masked value; leave the field out to keep the stored key")
		default:
			value := apiKey
			steps = append(steps, settingStep{field: "gemini_api_key", apply: func() error {
				return db.SetSystemConfig(ctx, "gemini_api_key", value)
			}})
		}
	}

	if req.AgentWebhookURL != nil {
		webhookURL := strings.TrimSpace(*req.AgentWebhookURL)
		switch {
		case webhookURL == "":
			steps = append(steps, settingStep{field: "agent_webhook_url", apply: func() error {
				return db.SetSystemConfig(ctx, "agent_webhook_url", "")
			}})
		case strings.Contains(webhookURL, "*"):
			return nil, invalidSettings("agent_webhook_url still contains the masked value; leave the field out to keep the stored URL")
		default:
			// Validated here, not at write time: this used to happen after the
			// Gemini key had already been persisted.
			if _, err := netguard.ValidateURL(webhookURL, false); err != nil {
				return nil, invalidSettings("invalid agent_webhook_url: %v", err)
			}
			value := webhookURL
			steps = append(steps, settingStep{field: "agent_webhook_url", apply: func() error {
				return db.SetSystemConfig(ctx, "agent_webhook_url", value)
			}})
		}
	}

	if req.TelemetryRetentionDays != nil {
		days := *req.TelemetryRetentionDays
		if days < minTelemetryRetentionDays || days > maxTelemetryRetentionDays {
			return nil, invalidSettings("telemetry_retention_days must be between %d and %d, got %d",
				minTelemetryRetentionDays, maxTelemetryRetentionDays, days)
		}
		steps = append(steps, settingStep{field: "telemetry_retention_days", apply: func() error {
			// Persist first, then update the process's copy. The other order
			// would leave the in-memory value already changed when the durable
			// write failed, so a restart would silently revert the setting —
			// and the comment claiming otherwise was simply wrong.
			if err := db.SetSystemConfig(ctx, "telemetry_retention_days", strconv.Itoa(days)); err != nil {
				return err
			}
			db.UpdateRetentionDays(ctx, days)
			return nil
		}})
	}

	if req.AdblockMatchMode != nil {
		mode := strings.ToLower(strings.TrimSpace(*req.AdblockMatchMode))
		if mode != "suffix" && mode != "exact" {
			return nil, invalidSettings("adblock_match_mode must be %q or %q, got %q", "suffix", "exact", *req.AdblockMatchMode)
		}
		steps = append(steps, settingStep{field: "adblock_match_mode", apply: func() error {
			return svc.Adblock().SetAdblockMatchMode(ctx, svc.StoreDB(), mode)
		}})
	}

	// Held back and appended last, whatever order the document listed it in.
	//
	// Enabling is not an ordinary field: it is the one setting that turns the
	// adblock layer live, and turning it on triggers a rebuild. If it ran
	// before the source policies, a request carrying both would bring adblock
	// up against the *previous* policy document, briefly enforce the old
	// source rules, and then rebuild a second time. Applying enablement last
	// means one rebuild, with the policies already in force. This ordering is
	// the base behaviour, and the validate-then-apply split must not lose it.
	var enableStep *settingStep
	if req.AdblockEnabled != nil {
		enabled := *req.AdblockEnabled
		enableStep = &settingStep{field: "adblock_enabled", apply: func() error {
			return svc.Adblock().SetAdblockEnabled(ctx, svc.StoreDB(), enabled)
		}}
	}

	if req.AdblockSourcePoliciesJSON != nil {
		// The service owns the rules so the API and any other caller share one
		// definition. Validated here as well as inside the setter, because this
		// document is one field among several and a bad document must be
		// rejected before any of them is written — not reported as a store
		// failure after the rest has been applied.
		document := *req.AdblockSourcePoliciesJSON
		if err := risk.ValidateAdblockSourcePoliciesJSON(document); err != nil {
			return nil, err
		}
		steps = append(steps, settingStep{field: "adblock_source_policies_json", apply: func() error {
			return svc.Adblock().SetAdblockSourcePoliciesJSON(ctx, svc.StoreDB(), document)
		}})
	}

	if enableStep != nil {
		steps = append(steps, *enableStep)
	}

	if len(steps) == 0 {
		return nil, nil
	}
	return steps, nil
}

// applySettings runs the steps in the order validate produced and stops at the
// first failure, so the fields after a failing one are not written.
func applySettings(steps []settingStep) error {
	for _, step := range steps {
		if err := step.apply(); err != nil {
			return fmt.Errorf("apply %s: %w", step.field, err)
		}
	}
	return nil
}
