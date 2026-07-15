package handlers

import (
	"time"

	"safe-zone/internal/observability"
	"safe-zone/internal/risk"
)

type Config struct {
	DeploymentTier      string
	RateLimitingEnabled bool
	SessionSecret       []byte
	AdminPassword       string
	AdminAPIKey         string
	PublicHost          string
	FeedKey             string
	FeedPreset          string
	FeedSources         []string
	FeedStaleAfter      time.Duration
}

type Handler struct {
	Risk    *risk.Service
	Metrics *observability.Registry
	Config  Config
}

func New(riskService *risk.Service, metrics *observability.Registry, cfg Config) *Handler {
	return &Handler{
		Risk:    riskService,
		Metrics: metrics,
		Config:  cfg,
	}
}
