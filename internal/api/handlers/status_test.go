package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
	"safe-zone/internal/observability"
	"safe-zone/internal/risk"
	"safe-zone/internal/serve"
	"safe-zone/internal/store"
)

func TestStatusEndpointHTTP(t *testing.T) {
	// Package handlers has no shadow TestMain pin; force the hermetic default.
	t.Setenv("SAFE_ZONE_ADBLOCK_SHADOW_EXACT_ENABLED", "false")
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
	if payload.Adblock.Exceptions.Configured {
		t.Fatal("expected exceptions disabled without config")
	}
	if payload.Adblock.Exceptions.Count != 0 {
		t.Fatalf("expected zero exceptions, got %d", payload.Adblock.Exceptions.Count)
	}
	shadow := payload.Adblock.ShadowExact
	if shadow.Enabled || shadow.Active {
		t.Fatalf("expected shadow disabled/inactive by default, got %+v", shadow)
	}
	if shadow.TargetScope != "exact" {
		t.Fatalf("expected target_scope exact, got %+v", shadow)
	}
	if shadow.Observations != shadow.WouldStillBlockContent+shadow.WouldAllowContent+
		shadow.ExplicitScopePreservedBlock+shadow.UnavailableOriginUnknown {
		t.Fatalf("observations must equal the primary sum: %+v", shadow)
	}
	if shadow.Observations != 0 || shadow.ExceptionOverlap != 0 {
		t.Fatalf("expected zero shadow counters, got %+v", shadow)
	}
	raw, err := json.Marshal(payload.Adblock)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	shadowWire, ok := wire["shadow_exact"].(map[string]any)
	if !ok {
		t.Fatalf("expected adblock.shadow_exact object, got %v", wire)
	}
	wantKeys := map[string]bool{
		"enabled": true, "active": true, "target_scope": true, "observations": true,
		"would_still_block_content": true, "would_allow_content": true,
		"explicit_scope_preserved_block": true, "unavailable_origin_unknown": true,
		"exception_overlap": true,
	}
	if len(shadowWire) != len(wantKeys) {
		t.Fatalf("unexpected shadow_exact keys, got %v", shadowWire)
	}
	for key := range shadowWire {
		if !wantKeys[key] {
			t.Fatalf("unexpected shadow_exact key %q leaking into public JSON: %v", key, shadowWire)
		}
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
	redisStatus, ok := payload["redis"].(map[string]any)
	if !ok {
		t.Fatalf("expected redis status object, got %#v", payload["redis"])
	}
	if redisStatus["status"] != "disabled" {
		t.Fatalf("expected disabled redis status, got %#v", redisStatus["status"])
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

// The status endpoint must expose aggregate exception state (configured,
// count, digest revision, reload outcome) without leaking raw config such as
// exception IDs or reasons.
func TestStatusEndpointReportsExceptionAggregates(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SAFE_ZONE_ADBLOCK_SOURCES", "")

	excBody := `{"version":1,"exceptions":[` +
		`{"id":"fp-status","domain":"status.example.com","scope":"exact",` +
		`"matched_rule":"status.example.com","source_id":"legacy",` +
		`"match_type":"suffix","reason":"INC-status verified"}` +
		`]}`
	excPath := filepath.Join(tempDir, "exceptions.json")
	if err := os.WriteFile(excPath, []byte(excBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_ZONE_ADBLOCK_EXCEPTIONS_FILE", excPath)

	dbPath := filepath.Join(tempDir, "status-exc.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeDB.Close() })

	riskService := risk.NewService(risk.Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              storeDB,
		AdblockFileRoot:    tempDir,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = riskService.Close() })

	handler := &Handler{Risk: riskService, Config: Config{DeploymentTier: "test"}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.StatusHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	var payload statusResponse
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Adblock == nil {
		t.Fatal("expected adblock status block")
	}
	exc := payload.Adblock.Exceptions
	if !exc.Configured || exc.Count != 1 {
		t.Fatalf("expected one configured exception, got %+v", exc)
	}
	if exc.Revision == "" || len(exc.Revision) != 32 {
		t.Fatalf("expected digest revision, got %+v", exc)
	}
	if !exc.LastReloadOK || exc.LastErrorClass != "" {
		t.Fatalf("expected clean reload, got %+v", exc)
	}
	if exc.ReloadSuccesses != 1 || exc.ReloadFailures != 0 {
		t.Fatalf("expected reload counters, got %+v", exc)
	}
	raw, err := json.Marshal(payload.Adblock)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "fp-status") || strings.Contains(string(raw), "INC-status") {
		t.Fatalf("status must not leak exception ids or reasons: %s", raw)
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
