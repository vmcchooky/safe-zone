import os
import re

api_path = "internal/api/handlers/api.go"
with open(api_path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix RateLimitingStatus
rate_limit_struct = """type RateLimitingStatus struct {
	Enabled bool `json:"enabled"`
}

type statusResponse struct {"""
content = content.replace('type statusResponse struct {', rate_limit_struct)
content = content.replace('RateLimiting   map[string]any', 'RateLimiting   *RateLimitingStatus')

# Fix missing imports: "fmt" and "net/url"
content = content.replace('"time"', '"time"\\n\\t"fmt"\\n\\t"net/url"')

# Fix a.validCSRFSources -> h.ValidCSRFSources
content = content.replace('a.validCSRFSources', 'h.ValidCSRFSources')
content = content.replace('a.verifyCSRF', 'h.VerifyCSRF')
content = content.replace('a.requireAuthFunc', 'h.RequireAuthFunc')
# Replace any leftover a.something with h.Something
content = re.sub(r'\\ba\\.(?=[a-zA-Z])', 'h.', content)
# And capitalize the first letter after h.
content = re.sub(r'h\\.([a-z])', lambda m: 'h.' + m.group(1).upper(), content)

with open(api_path, "w", encoding="utf-8") as f:
    f.write(content)
