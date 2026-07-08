package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/observability"
	"safe-zone/internal/serve"
)

func TestStatusEndpointHTTP(t *testing.T) {
	ts := newHandlerTestServer(t)

	resp, err := ts.Client.Get(ts.Server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected application/json content type, got %q", got)
	}
	if resp.Header.Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID response header")
	}

	var payload statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload.Service != "core-api" {
		t.Fatalf("expected core-api service, got %q", payload.Service)
	}
	if payload.Status != "ok" {
		t.Fatalf("expected ok status, got %q", payload.Status)
	}
	if payload.Mode != "api" {
		t.Fatalf("expected api mode, got %q", payload.Mode)
	}
	if payload.DeploymentTier != "test" {
		t.Fatalf("expected test deployment tier, got %q", payload.DeploymentTier)
	}
	if payload.Redis == nil || payload.Redis.Status != "disabled" {
		t.Fatalf("expected disabled redis status, got %#v", payload.Redis)
	}
	if payload.AnalysisConfig == nil || !payload.AnalysisConfig.Enabled {
		t.Fatalf("expected enabled analysis config reload status, got %#v", payload.AnalysisConfig)
	}
	if payload.AnalysisConfig.Revision == "" {
		t.Fatal("expected non-empty analysis config revision")
	}
	if payload.AnalysisConfig.LastReloadSource != "startup" {
		t.Fatalf("expected startup reload source, got %q", payload.AnalysisConfig.LastReloadSource)
	}
	if payload.FeedSync == nil || payload.FeedSync.Status != "disabled" {
		t.Fatalf("expected disabled feed sync status, got %#v", payload.FeedSync)
	}
	if payload.Adblock == nil {
		t.Fatal("expected adblock status block")
	}
	if len(payload.Endpoints) == 0 {
		t.Fatal("expected endpoint list")
	}
	if payload.Time == "" {
		t.Fatal("expected timestamp")
	}
}

func TestMetricsEndpointHTTP(t *testing.T) {
	ts := newHandlerTestServer(t)

	warmResp, err := ts.Client.Get(ts.Server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	warmResp.Body.Close()

	resp, err := ts.Client.Get(ts.Server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["service"] != "core-api" {
		t.Fatalf("expected core-api service, got %#v", payload["service"])
	}
	feedSync, ok := payload["feed_sync"].(map[string]any)
	if !ok {
		t.Fatalf("expected feed_sync object, got %#v", payload["feed_sync"])
	}
	if feedSync["status"] != "disabled" {
		t.Fatalf("expected disabled feed_sync status, got %#v", feedSync["status"])
	}
	metrics, ok := payload["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected metrics object, got %#v", payload["metrics"])
	}
	if _, ok := metrics["request_summary"].(map[string]any); !ok {
		t.Fatalf("expected request_summary map, got %#v", metrics["request_summary"])
	}
	reloadStatus, ok := payload["analysis_config_reload"].(map[string]any)
	if !ok {
		t.Fatalf("expected analysis_config_reload object, got %#v", payload["analysis_config_reload"])
	}
	if reloadStatus["revision"] == "" {
		t.Fatalf("expected analysis config revision, got %#v", reloadStatus["revision"])
	}
}

func TestVersionEndpointReportsBuildMetadata(t *testing.T) {
	restore := overrideBuildInfo("1.3.0", "abc123def", "2026-05-26T12:00:00Z", "safe-zone-core-api:1.3.0-abc123def", "https://github.com/quorix/safe-zone")
	defer restore()

	handler := &Handler{Config: Config{DeploymentTier: "shared-vps"}}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/version", nil)

	handler.VersionHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload buildinfo.Metadata
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload.Service != "core-api" {
		t.Fatalf("expected core-api service, got %q", payload.Service)
	}
	if payload.Version != "1.3.0" {
		t.Fatalf("expected version 1.3.0, got %q", payload.Version)
	}
	if payload.GitCommit != "abc123def" {
		t.Fatalf("expected git commit abc123def, got %q", payload.GitCommit)
	}
	if payload.BuildTime != "2026-05-26T12:00:00Z" {
		t.Fatalf("expected build time, got %q", payload.BuildTime)
	}
	if payload.ImageTag != "safe-zone-core-api:1.3.0-abc123def" {
		t.Fatalf("expected image tag, got %q", payload.ImageTag)
	}
	if payload.SourceRepo != "https://github.com/quorix/safe-zone" {
		t.Fatalf("expected source repo, got %q", payload.SourceRepo)
	}
	if payload.DeploymentTier != "shared-vps" {
		t.Fatalf("expected deployment tier shared-vps, got %q", payload.DeploymentTier)
	}
}

func TestVersionEndpointRejectsNonGet(t *testing.T) {
	handler := &Handler{Config: Config{DeploymentTier: "test"}}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/version", nil)

	handler.VersionHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", recorder.Code)
	}
}

func TestLogRequestsSkipsMetricsAfterRecoveredPanic(t *testing.T) {
	metrics := observability.NewRegistry()
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	handler := serve.WithRequestID(httputil.LogRequests("core-api", metrics)(serve.Recovery(panicHandler, metrics)))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/panic", nil)

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	snapshot := metrics.Snapshot()
	summary, ok := snapshot.RequestSummary["GET /panic 500"]
	if !ok {
		t.Fatalf("expected panic request metric, got %#v", snapshot.RequestSummary)
	}
	if summary.Count != 1 {
		t.Fatalf("expected panic request metric to be observed once, got %d", summary.Count)
	}
}

func overrideBuildInfo(version, gitCommit, buildTime, imageTag, sourceRepo string) func() {
	prevVersion := buildinfo.Version
	prevGitCommit := buildinfo.GitCommit
	prevBuildTime := buildinfo.BuildTime
	prevImageTag := buildinfo.ImageTag
	prevSourceRepo := buildinfo.SourceRepo

	buildinfo.Version = version
	buildinfo.GitCommit = gitCommit
	buildinfo.BuildTime = buildTime
	buildinfo.ImageTag = imageTag
	buildinfo.SourceRepo = sourceRepo

	return func() {
		buildinfo.Version = prevVersion
		buildinfo.GitCommit = prevGitCommit
		buildinfo.BuildTime = prevBuildTime
		buildinfo.ImageTag = prevImageTag
		buildinfo.SourceRepo = prevSourceRepo
	}
}

func TestHealthHandler(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	HealthHandler("core-api")(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	body, err := io.ReadAll(recorder.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) == "" {
		t.Fatal("expected health body")
	}
}
