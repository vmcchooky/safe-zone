import os
import re

test_path = "internal/api/handlers/api_test.go"
with open(test_path, "r", encoding="utf-8") as f:
    content = f.read()

# Replace any remaining `app.` with `api.`
content = content.replace("app.", "api.")

# Fix Handler initialization
bad_init = "api := &Handler{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond, ConfigReloadEnabled: true}), metrics: observability.NewRegistry()}"
good_init = """r := risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond, ConfigReloadEnabled: true})
	api := New(r, observability.NewRegistry(), Config{DeploymentTier: "budget-vps"})"""
content = content.replace(bad_init, good_init)

# Fix httputil.LogRequests
content = re.sub(r'httputil\.LogRequests\("core-api", (.*?), api\.Metrics\)', r'httputil.LogRequests("core-api", api.Metrics)(\1)', content)

# Fix missing `statusResponse` type in tests if any? I will just use `map[string]any` or add statusResponse back
if "type statusResponse" not in content and "statusResponse" in content:
    content = content.replace("package handlers", "package handlers\n\ntype statusResponse struct {\n\tService        string                           `json:\"service\"`\n\tStatus         string                           `json:\"status\"`\n\tMode           string                           `json:\"mode,omitempty\"`\n\tDeploymentTier string                           `json:\"deployment_tier,omitempty\"`\n\tRedis          *risk.CacheStatus                `json:\"redis,omitempty\"`\n\tAnalysisConfig *risk.AnalysisConfigReloadStatus `json:\"analysis_config_reload,omitempty\"`\n\tFeedSync       *feed.StatusSummary              `json:\"feed_sync,omitempty\"`\n\tEndpoints      []string                         `json:\"endpoints,omitempty\"`\n\tRateLimiting   *RateLimitingStatus              `json:\"rate_limiting,omitempty\"`\n\tTime           string                           `json:\"time\"`\n}\n")

# Replace api.statusHandler -> api.StatusHandler
content = re.sub(r'api\.([a-z])', lambda m: 'api.' + m.group(1).upper(), content)
# Except api.Metrics, api.Risk, api.Config which are already upper case

with open(test_path, "w", encoding="utf-8") as f:
    f.write(content)
