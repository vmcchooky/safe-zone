import os
import re

test_path = "internal/api/handlers/api_test.go"
with open(test_path, "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace("package main", "package handlers")
content = content.replace("&app{", "&Handler{")
content = content.replace("app :=", "api :=")

# Replace metrics initialization
content = content.replace("metrics:        observability.NewRegistry(),", "Metrics:        observability.NewRegistry(),")
content = content.replace("risk:           r,", "Risk:           r,")
content = content.replace("deploymentTier: \"test\",", "Config: Config{DeploymentTier: \"test\", ")
# We need to close the brace for Config.
# We will do a generic replacement for the `Handler` fields.

# Since `api_test.go` may use a lot of fields directly like `api.metrics`, we will do what we did in `fix_api.py`.
content = content.replace("api.risk.", "api.Risk.")
content = content.replace("api.metrics", "api.Metrics")
content = content.replace("api.deploymentTier", "api.Config.DeploymentTier")
content = content.replace("api.sessionSecret", "api.Config.SessionSecret")
content = content.replace("logRequests(", "httputil.LogRequests(")
content = content.replace("func (a *app)", "func (h *Handler)")
# Update method calls
content = re.sub(r'api\.([a-z])', lambda m: 'api.' + m.group(1).upper(), content)
content = content.replace('"safe-zone/internal/risk"', '"safe-zone/internal/risk"\n\t"safe-zone/internal/api/httputil"')

with open(test_path, "w", encoding="utf-8") as f:
    f.write(content)
