import os

main_path = "cmd/core-api/main.go"
with open(main_path, "r", encoding="utf-8") as f:
    content = f.read()

# We will cut the file at `mux := http.NewServeMux()`
cut_str = "mux := http.NewServeMux()"
idx = content.find(cut_str)

new_content = content[:idx]

# Remove the `type analyzeRequest` and `type statusResponse` and `type app` stuff.
# They are from line 32 to `func main() {`
idx_main = new_content.find("func main() {")
idx_types = new_content.find("type analyzeRequest struct {")
new_content = new_content[:idx_types] + new_content[idx_main:]

# Now replace `api := &app{` with `cfg := handlers.Config{`
new_content = new_content.replace("api := &app{", "cfg := handlers.Config{")
new_content = new_content.replace('risk:           risk.NewServiceFromEnvForRole("core-api"),', '')
new_content = new_content.replace('metrics:        observability.NewRegistry(),', '')
new_content = new_content.replace('deploymentTier: ', 'DeploymentTier: ')
new_content = new_content.replace('sessionSecret:  ', 'SessionSecret:  ')
new_content = new_content.replace('adminPassword:  ', 'AdminPassword:  ')
new_content = new_content.replace('adminAPIKey:    ', 'AdminAPIKey:    ')
new_content = new_content.replace('publicHost:     ', 'PublicHost:     ')
new_content = new_content.replace('feedKey:        ', 'FeedKey:        ')
new_content = new_content.replace('feedPreset:     ', 'FeedPreset:     ')
new_content = new_content.replace('feedSources:    ', 'FeedSources:    ')
new_content = new_content.replace('feedStaleAfter: ', 'FeedStaleAfter: ')

# We need risk service and metrics initialized before `cfg`.
risk_init = """	riskService := risk.NewServiceFromEnvForRole("core-api")
	metrics := observability.NewRegistry()
	"""
new_content = new_content.replace("cfg := handlers.Config{", risk_init + "cfg := handlers.Config{")

# Fix `defer func()`
new_content = new_content.replace("if err := api.risk.Close();", "if err := riskService.Close();")
# Fix `logCacheStatus`
new_content = new_content.replace('logCacheStatus("core-api", api.risk)', '/* logCacheStatus removed */')
new_content = new_content.replace('logAnalysisConfigReloadStatus("core-api", api.risk)', '/* logAnalysisConfigReloadStatus removed */')
new_content = new_content.replace('api.rateLimiter = tiered', '')

# Fix `agent.NewAuditTask` and others using `api.risk`
new_content = new_content.replace('api.risk.', 'riskService.')

# Add the router and server code at the end
router_code = """
	h := handlers.New(riskService, metrics, cfg)
	mux := server.NewRouter(h, agentEngine, handlers.AssetsFS)

	var handler http.Handler = mux
	if tiered != nil {
		handler = tiered.Wrap(mux)
	}

	recoveryHandler := serve.Recovery(handler, metrics)
	requestIDHandler := serve.WithRequestID(httputil.LogRequests("core-api", metrics)(recoveryHandler))

	srv := &http.Server{
		Addr:              addr,
		Handler:           requestIDHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logjson.Info("service listening", map[string]any{
		"service": "core-api",
		"addr":    addr,
	})
	if err := serve.RunHTTPServer(srv, shutdownTimeout); err != nil {
		logjson.Error("core-api server stopped with error", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
		os.Exit(1)
	}
}
"""

new_content += router_code

# Add missing imports: handlers, server, httputil
# We will just write it and run goimports.
with open(main_path, "w", encoding="utf-8") as f:
    f.write(new_content)
