import os
import re

main_path = "cmd/core-api/main.go"
with open(main_path, "r", encoding="utf-8") as f:
    content = f.read()

# We will move all handlers to internal/api/handlers/api.go
# Let's extract everything from `func healthHandler` to the end.
match = re.search(r'func healthHandler\(.*?\).*', content, re.DOTALL)
if not match:
    print("Could not find healthHandler")
    exit(1)

handlers_content = match.group(0)

# Remove the helpers we already extracted to httputil
helpers_to_remove = [
    r'func logRequests.*?^}',
    r'type statusLoggingResponseWriter.*?^}',
    r'func \(w \*statusLoggingResponseWriter\) WriteHeader.*?^}',
    r'func \(w \*statusLoggingResponseWriter\) Write.*?^}',
    r'func writeJSON.*?^}',
    r'func writeError.*?^}',
    r'func sanitizeLog.*?^}',
    r'func extractClientInfo.*?^}'
]
for pattern in helpers_to_remove:
    handlers_content = re.sub(pattern, '', handlers_content, flags=re.MULTILINE | re.DOTALL)

# Replace (a *app) with (h *Handler)
handlers_content = re.sub(r'\(a \*app\)', '(h *Handler)', handlers_content)

# Replace a.risk with h.Risk
handlers_content = re.sub(r'\ba\.risk\b', 'h.Risk', handlers_content)
# Replace a.metrics with h.Metrics
handlers_content = re.sub(r'\ba\.metrics\b', 'h.Metrics', handlers_content)
# Replace a.deploymentTier with h.Config.DeploymentTier
handlers_content = re.sub(r'\ba\.deploymentTier\b', 'h.Config.DeploymentTier', handlers_content)
# Replace a.sessionSecret with h.Config.SessionSecret
handlers_content = re.sub(r'\ba\.sessionSecret\b', 'h.Config.SessionSecret', handlers_content)
# Replace a.adminPassword with h.Config.AdminPassword
handlers_content = re.sub(r'\ba\.adminPassword\b', 'h.Config.AdminPassword', handlers_content)
# Replace a.adminAPIKey with h.Config.AdminAPIKey
handlers_content = re.sub(r'\ba\.adminAPIKey\b', 'h.Config.AdminAPIKey', handlers_content)
# Replace a.publicHost with h.Config.PublicHost
handlers_content = re.sub(r'\ba\.publicHost\b', 'h.Config.PublicHost', handlers_content)
# Replace a.feedStatus with h.feedStatus
handlers_content = re.sub(r'\ba\.feedStatus\b', 'h.FeedStatus', handlers_content)
# Replace a.feedKey, a.feedPreset, a.feedSources, a.feedStaleAfter
handlers_content = re.sub(r'\ba\.feedKey\b', 'h.Config.FeedKey', handlers_content)
handlers_content = re.sub(r'\ba\.feedPreset\b', 'h.Config.FeedPreset', handlers_content)
handlers_content = re.sub(r'\ba\.feedSources\b', 'h.Config.FeedSources', handlers_content)
handlers_content = re.sub(r'\ba\.feedStaleAfter\b', 'h.Config.FeedStaleAfter', handlers_content)
# Replace a.rateLimiter with h.Config.RateLimiterEnabled or something
handlers_content = re.sub(r'\ba\.rateLimiter != nil\b', 'true /* TODO fix ratelimiter status */', handlers_content)

# Replace writeJSON, writeError, extractClientInfo, sanitizeLog with httputil.X
handlers_content = re.sub(r'\bwriteJSON\(', 'httputil.WriteJSON(', handlers_content)
handlers_content = re.sub(r'\bwriteError\(', 'httputil.WriteError(', handlers_content)
handlers_content = re.sub(r'\bextractClientInfo\(', 'httputil.ExtractClientInfo(', handlers_content)
handlers_content = re.sub(r'\bsanitizeLog\(', 'httputil.SanitizeLog(', handlers_content)

# Fix healthHandler signature
handlers_content = re.sub(r'func healthHandler\(service string\) http.HandlerFunc', 'func HealthHandler(service string) http.HandlerFunc', handlers_content)

# Make methods public
handlers_content = re.sub(r'func \(h \*Handler\) ([a-z])', lambda m: f'func (h *Handler) {m.group(1).upper()}', handlers_content)

api_go = """package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
	"crypto/subtle"
	"crypto/sha256"

	"safe-zone/internal/agent"
	"safe-zone/internal/analysis"
	"safe-zone/internal/auth"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

// types that were at the top of main.go
type statusResponse struct {
	Service        string                           `json:"service"`
	Status         string                           `json:"status"`
	Mode           string                           `json:"mode,omitempty"`
	DeploymentTier string                           `json:"deployment_tier,omitempty"`
	Redis          *risk.CacheStatus                `json:"redis,omitempty"`
	AnalysisConfig *risk.AnalysisConfigReloadStatus `json:"analysis_config_reload,omitempty"`
	FeedSync       *feed.StatusSummary              `json:"feed_sync,omitempty"`
	Endpoints      []string                         `json:"endpoints,omitempty"`
	RateLimiting   map[string]any                   `json:"rate_limiting,omitempty"`
	Time           string                           `json:"time"`
}

type analyzeRequest struct {
	Domain string `json:"domain"`
}

""" + handlers_content

os.makedirs("internal/api/handlers", exist_ok=True)
with open("internal/api/handlers/api.go", "w", encoding="utf-8") as f:
    f.write(api_go)

print("Created internal/api/handlers/api.go")
