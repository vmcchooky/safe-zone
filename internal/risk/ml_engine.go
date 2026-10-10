package risk

import (
	"safe-zone/internal/analysis"
)

// MLEngine owns all machine-learning subsystem state: the domain
// classifier, its mode/canary/telemetry, and the URL classifier with its
// shadow sampling, telemetry, operational baseline and feedback backend.
// Service holds exactly one, constructed in NewService; methods that need
// ML behavior live on the engine, with request contexts and feed lookups
// passed explicitly rather than reached through the Service.
type MLEngine struct {
	mlClassifier analysis.DomainClassifier
	mlMode       analysis.MLMode
	mlCanary     MLCanaryConfig
	mlTelemetry  mlTelemetry

	urlMLClassifier analysis.URLClassifier
	urlMLMode       analysis.MLMode
	urlMLShadow     URLMLShadowConfig
	urlMLTelemetry  urlMLTelemetry
	// urlMLOpsBaseline is an optional frozen operational drift reference
	// loaded from real shadow traffic. Load failures are fail-open.
	urlMLOpsBaseline           *URLOperationalBaseline
	urlMLOpsBaselineFailed     bool
	urlMLOpsBaselineErrorClass string
	// urlMLFeedback correlates opaque event fingerprints with caller labels.
	// Backed by memory (ephemeral) or SQLite (durable, bounded) depending on
	// URLMLFeedbackConfig.
	urlMLFeedback urlFeedbackBackend
}
