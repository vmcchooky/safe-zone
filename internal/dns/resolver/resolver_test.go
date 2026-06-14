//go:build ignore

package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
	"safe-zone/internal/observability"
	"safe-zone/internal/ratelimit"
	"safe-zone/internal/risk"
	"safe-zone/internal/serve"
	"safe-zone/internal/store"
)

func TestStatusHandlerRoot(t *testing.T) {
	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		upstreamDoHURL: "https://cloudflare-dns.com/dns-query",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	app.statusHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload["service"] != "dns-resolver" {
		t.Fatalf("expected dns-resolver service, got %#v", payload["service"])
	}
	if payload["status"] != "ok" {
		t.Fatalf("expected ok status, got %#v", payload["status"])
	}
	if payload["mode"] != "doh" {
		t.Fatalf("expected doh mode, got %#v", payload["mode"])
	}
	if payload["deployment_tier"] != "budget-vps" {
		t.Fatalf("expected budget-vps deployment tier, got %#v", payload["deployment_tier"])
	}
	if payload["upstream_doh"] != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("unexpected upstream_doh: %#v", payload["upstream_doh"])
	}
	if payload["time"] == "" {
		t.Fatal("expected time in status response")
	}

	redis, ok := payload["redis"].(map[string]any)
	if !ok {
		t.Fatalf("expected redis object, got %#v", payload["redis"])
	}
	if redis["status"] != "disabled" {
		t.Fatalf("expected disabled redis status, got %#v", redis["status"])
	}
	reloadStatus, ok := payload["analysis_config_reload"].(map[string]any)
	if !ok {
		t.Fatalf("expected analysis_config_reload object, got %#v", payload["analysis_config_reload"])
	}
	if reloadStatus["revision"] == "" {
		t.Fatalf("expected analysis config revision, got %#v", reloadStatus["revision"])
	}
	if reloadStatus["last_reload_source"] != "startup" {
		t.Fatalf("expected startup reload source, got %#v", reloadStatus["last_reload_source"])
	}

	endpoints, ok := payload["endpoints"].([]any)
	if !ok || len(endpoints) == 0 {
		t.Fatalf("expected endpoints list, got %#v", payload["endpoints"])
	}
}

func TestStatusHandlerRejectsNonRootPath(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/status", nil)

	app.statusHandler(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}

func TestMetricsHandlerRoot(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", app.metricsHandler)
	testServer := httptest.NewServer(serve.WithRequestID(logRequests("dns-resolver", mux, app.metrics)))
	defer testServer.Close()

	response, err := http.Get(testServer.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if response.Header.Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID response header")
	}

	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["service"] != "dns-resolver" {
		t.Fatalf("expected dns-resolver service, got %#v", payload["service"])
	}
	reloadStatus, ok := payload["analysis_config_reload"].(map[string]any)
	if !ok {
		t.Fatalf("expected analysis_config_reload object, got %#v", payload["analysis_config_reload"])
	}
	if reloadStatus["revision"] == "" {
		t.Fatalf("expected analysis config revision in metrics payload, got %#v", reloadStatus["revision"])
	}
	metrics, ok := payload["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected metrics object, got %#v", payload["metrics"])
	}
	if _, ok := metrics["request_summary"].(map[string]any); !ok {
		t.Fatalf("expected request_summary map, got %#v", metrics["request_summary"])
	}
}

func TestVersionHandlerReportsBuildMetadata(t *testing.T) {
	restore := overrideResolverBuildInfo("1.3.0", "abc123def", "2026-05-26T12:00:00Z", "safe-zone-dns-resolver:1.3.0-abc123def", "https://github.com/quorix/safe-zone")
	defer restore()

	app := &app{deploymentTier: "shared-vps"}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	app.versionHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload buildinfo.Metadata
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload.Service != "dns-resolver" {
		t.Fatalf("expected dns-resolver service, got %q", payload.Service)
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
	if payload.ImageTag != "safe-zone-dns-resolver:1.3.0-abc123def" {
		t.Fatalf("expected image tag, got %q", payload.ImageTag)
	}
	if payload.SourceRepo != "https://github.com/quorix/safe-zone" {
		t.Fatalf("expected source repo, got %q", payload.SourceRepo)
	}
	if payload.DeploymentTier != "shared-vps" {
		t.Fatalf("expected deployment tier shared-vps, got %q", payload.DeploymentTier)
	}
}

func TestVersionHandlerRejectsNonGet(t *testing.T) {
	app := &app{deploymentTier: "budget-vps"}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/version", nil)
	app.versionHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", recorder.Code)
	}
}

func TestLogRequestsSkipsMetricsAfterRecoveredPanic(t *testing.T) {
	metrics := observability.NewRegistry()
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	handler := serve.WithRequestID(logRequests("dns-resolver", serve.Recovery(panicHandler, metrics), metrics))

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

func overrideResolverBuildInfo(version, gitCommit, buildTime, imageTag, sourceRepo string) func() {
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

func TestDoHUpstreamFailureCounter(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))
	defer mockUpstream.Close()

	app := &app{
		risk: risk.NewService(risk.Options{
			AnalysisConfig: config.DefaultAnalysisConfig(),
			RedisTimeout:   10 * time.Millisecond,
		}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		upstreamDoHURL: mockUpstream.URL,
		upstreamClient: mockUpstream.Client(),
		blockPageIP:    "127.0.0.1",
		dnsTTL:         60,
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
	request.Header.Set("Content-Type", "application/dns-message")

	app.dohHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 even on DNS SERVFAIL response, got %d", recorder.Code)
	}

	if got := app.metrics.Snapshot().Counters["upstream_doh_failures_total"]; got != 1 {
		t.Fatalf("expected upstream_doh_failures_total=1, got %d", got)
	}
}

func TestBlockedDNSResponseStrategies(t *testing.T) {
	tests := []struct {
		name          string
		strategy      string
		qtype         uint16
		expectedRcode int
		expectedIP    string
		expectedType  uint16
	}{
		{
			name:          "sinkhole A returns configured block page IP",
			strategy:      blockStrategySinkhole,
			qtype:         dns.TypeA,
			expectedRcode: dns.RcodeSuccess,
			expectedIP:    "203.0.113.10",
			expectedType:  dns.TypeA,
		},
		{
			name:          "nxdomain returns name error without answers",
			strategy:      blockStrategyNXDomain,
			qtype:         dns.TypeA,
			expectedRcode: dns.RcodeNameError,
		},
		{
			name:          "refused returns refused without answers",
			strategy:      blockStrategyRefused,
			qtype:         dns.TypeA,
			expectedRcode: dns.RcodeRefused,
		},
		{
			name:          "nullip A returns IPv4 null address",
			strategy:      blockStrategyNullIP,
			qtype:         dns.TypeA,
			expectedRcode: dns.RcodeSuccess,
			expectedIP:    "0.0.0.0",
			expectedType:  dns.TypeA,
		},
		{
			name:          "nullip AAAA returns IPv6 null address",
			strategy:      blockStrategyNullIP,
			qtype:         dns.TypeAAAA,
			expectedRcode: dns.RcodeSuccess,
			expectedIP:    "::",
			expectedType:  dns.TypeAAAA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &app{
				blockPageIP:   "203.0.113.10",
				blockStrategy: tt.strategy,
				dnsTTL:        60,
			}
			query := new(dns.Msg)
			query.SetQuestion(dns.Fqdn("blocked.example"), tt.qtype)

			wire, err := app.blockedDNSResponse(query)
			if err != nil {
				t.Fatalf("blockedDNSResponse failed: %v", err)
			}

			response := new(dns.Msg)
			if err := response.Unpack(wire); err != nil {
				t.Fatalf("unpack blocked response: %v", err)
			}

			if response.Rcode != tt.expectedRcode {
				t.Fatalf("expected rcode %s, got %s", dns.RcodeToString[tt.expectedRcode], dns.RcodeToString[response.Rcode])
			}
			if tt.expectedIP == "" {
				if len(response.Answer) != 0 {
					t.Fatalf("expected no answers, got %d", len(response.Answer))
				}
				return
			}
			if len(response.Answer) != 1 {
				t.Fatalf("expected 1 answer, got %d", len(response.Answer))
			}

			switch tt.expectedType {
			case dns.TypeA:
				record, ok := response.Answer[0].(*dns.A)
				if !ok {
					t.Fatalf("expected A answer, got %T", response.Answer[0])
				}
				if record.A.String() != tt.expectedIP {
					t.Fatalf("expected A %s, got %s", tt.expectedIP, record.A.String())
				}
			case dns.TypeAAAA:
				record, ok := response.Answer[0].(*dns.AAAA)
				if !ok {
					t.Fatalf("expected AAAA answer, got %T", response.Answer[0])
				}
				if record.AAAA.String() != tt.expectedIP {
					t.Fatalf("expected AAAA %s, got %s", tt.expectedIP, record.AAAA.String())
				}
			}
		})
	}
}

func TestResolverClientGroupPolicy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test-resolver.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}

	app := &app{
		risk: risk.NewService(risk.Options{
			AnalysisConfig: config.DefaultAnalysisConfig(),
			RedisTimeout:   10 * time.Millisecond,
			Store:          storeDB,
		}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		upstreamDoHURL: "https://cloudflare-dns.com/dns-query",
	}
	defer func() {
		_ = app.risk.Close()
	}()

	// Setup a group that blocks adult content
	db := app.risk.StoreDB()
	adultGroupID, err := db.CreateGroup(context.Background(), "adult-blocker", "Blocks adult content", []string{"adult"}, false, false)
	if err != nil {
		t.Fatal(err)
	}

	// Map IP "192.168.2.10" to this group
	if _, err := db.AddMappingInt(context.Background(), "ip", "192.168.2.10", adultGroupID); err != nil {
		t.Fatal(err)
	}

	// Case 1: Client with IP 192.168.2.10 queries policy for xvideos.porn
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/policy?domain=xvideos.porn", nil)
	request.Header.Set("X-Forwarded-For", "192.168.2.10")

	app.policyHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload policyResponse
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload.Policy.Policy != "block" {
		t.Fatalf("expected block policy, got %s", payload.Policy.Policy)
	}
	if payload.Policy.Result.Category != "adult" {
		t.Fatalf("expected category adult, got %s", payload.Policy.Result.Category)
	}

	// Case 2: Client with IP 192.168.2.20 (defaults to default group) queries policy for xvideos.porn
	recorderDefault := httptest.NewRecorder()
	requestDefault := httptest.NewRequest(http.MethodGet, "/v1/policy?domain=xvideos.porn", nil)
	requestDefault.Header.Set("X-Forwarded-For", "192.168.2.20")

	app.policyHandler(recorderDefault, requestDefault)

	var payloadDefault policyResponse
	if err := json.NewDecoder(recorderDefault.Body).Decode(&payloadDefault); err != nil {
		t.Fatal(err)
	}

	if payloadDefault.Policy.Policy != "allow" {
		t.Fatalf("expected allow policy for default group client, got %s", payloadDefault.Policy.Policy)
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate self-signed cert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one certificate in the chain")
	}
	if cert.PrivateKey == nil {
		t.Fatal("expected private key to be set")
	}
}

func TestDoTHandlerBasic(t *testing.T) {
	// 1. Mock Upstream DoH HTTP Server
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := readDNSMessage(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			http.Error(w, "invalid dns msg", http.StatusBadRequest)
			return
		}

		resp := new(dns.Msg)
		resp.SetReply(query)
		if len(query.Question) > 0 {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("93.184.216.34"),
			})
		}

		respWire, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respWire)
	}))
	defer mockUpstream.Close()

	// 2. Setup SQLite DB Store with explicit policies
	dbPath := filepath.Join(t.TempDir(), "test-dot.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}

	// Create threat override for adult content / block
	_, err = storeDB.CreateGroup(context.Background(), "malicious-blocker", "Blocks malicious sites", []string{"malicious"}, false, false)
	if err != nil {
		t.Fatal(err)
	}

	// Add mock override for a bad domain
	err = storeDB.UpsertOverride(context.Background(), "bocongan-verify.xyz", "block", "Mock malicious site")
	if err != nil {
		t.Fatal(err)
	}

	app := &app{
		risk: risk.NewService(risk.Options{
			AnalysisConfig: config.DefaultAnalysisConfig(),
			RedisTimeout:   10 * time.Millisecond,
			Store:          storeDB,
		}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		upstreamDoHURL: mockUpstream.URL,
		upstreamClient: mockUpstream.Client(),
		blockPageIP:    "127.0.0.1",
		dnsTTL:         60,
	}
	defer func() {
		_ = app.risk.Close()
	}()

	// 3. Start DoT server locally on random port via tls.Listener
	selfCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{selfCert},
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	dotServer := &dns.Server{
		Listener: l,
		Net:      "tcp-tls",
		Handler:  dns.HandlerFunc(app.dotHandler),
	}

	go func() {
		_ = dotServer.ActivateAndServe()
	}()
	defer func() {
		_ = dotServer.Shutdown()
	}()

	// 4. Test Client
	client := &dns.Client{
		Net: "tcp-tls",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Timeout: 2 * time.Second,
	}

	serverAddr := l.Addr().String()

	t.Run("Allow Query - Forward to Upstream", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

		r, _, err := client.Exchange(m, serverAddr)
		if err != nil {
			t.Fatalf("DoT exchange failed: %v", err)
		}
		if r.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected RcodeSuccess, got %s", dns.RcodeToString[r.Rcode])
		}
		if len(r.Answer) == 0 {
			t.Fatal("expected answers from mock upstream")
		}
		aRecord, ok := r.Answer[0].(*dns.A)
		if !ok {
			t.Fatal("expected A record answer")
		}
		if aRecord.A.String() != "93.184.216.34" {
			t.Fatalf("expected IP 93.184.216.34, got %s", aRecord.A.String())
		}
	})

	t.Run("Block Query - Return Block Page IP", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("bocongan-verify.xyz"), dns.TypeA)

		r, _, err := client.Exchange(m, serverAddr)
		if err != nil {
			t.Fatalf("DoT exchange failed: %v", err)
		}
		if r.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected RcodeSuccess, got %s", dns.RcodeToString[r.Rcode])
		}
		if len(r.Answer) == 0 {
			t.Fatal("expected block page answer")
		}
		aRecord, ok := r.Answer[0].(*dns.A)
		if !ok {
			t.Fatal("expected A record answer")
		}
		if aRecord.A.String() != "127.0.0.1" {
			t.Fatalf("expected Block Page IP 127.0.0.1, got %s", aRecord.A.String())
		}
	})
}

func TestDoTHandlerRateLimiter(t *testing.T) {
	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		blockPageIP:    "127.0.0.1",
		dnsTTL:         60,
		dotLimiter:     ratelimit.New(0.1, 0), // Cực kỳ hạn chế
	}
	defer func() {
		_ = app.risk.Close()
		app.dotLimiter.Close()
	}()

	// Sinh SSL tự ký và tạo listener
	selfCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{selfCert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	dotServer := &dns.Server{
		Listener: l,
		Net:      "tcp-tls",
		Handler:  dns.HandlerFunc(app.dotHandler),
	}
	go func() { _ = dotServer.ActivateAndServe() }()
	defer func() { _ = dotServer.Shutdown() }()

	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Timeout:   2 * time.Second,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	// Cuộc gọi đầu tiên có thể được chấp nhận hoặc bị từ chối tùy thuộc vào việc burst = 0.
	// Nhưng chắc chắn cuộc gọi thứ 2 liên tiếp sẽ bị chặn vì RPM = 0.1, burst = 0.
	_, _, _ = client.Exchange(m, l.Addr().String())
	r, _, err := client.Exchange(m, l.Addr().String())
	if err != nil {
		t.Fatalf("DoT exchange failed: %v", err)
	}

	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("expected RcodeRefused due to rate limit, got %s", dns.RcodeToString[r.Rcode])
	}
}

func TestDoTHandlerConcurrent(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := readDNSMessage(w, r)
		query := new(dns.Msg)
		_ = query.Unpack(wire)

		resp := new(dns.Msg)
		resp.SetReply(query)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.1.1.1"),
		})
		respWire, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(respWire)
	}))
	defer mockUpstream.Close()

	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		upstreamDoHURL: mockUpstream.URL,
		upstreamClient: mockUpstream.Client(),
		blockPageIP:    "127.0.0.1",
		dnsTTL:         60,
		dotLimiter:     ratelimit.New(1000, 100), // Cực kỳ rộng rãi
	}
	defer func() {
		_ = app.risk.Close()
		app.dotLimiter.Close()
	}()

	selfCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{selfCert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	dotServer := &dns.Server{
		Listener: l,
		Net:      "tcp-tls",
		Handler:  dns.HandlerFunc(app.dotHandler),
	}
	go func() { _ = dotServer.ActivateAndServe() }()
	defer func() { _ = dotServer.Shutdown() }()

	var wg sync.WaitGroup
	concurrentRequests := 10

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			client := &dns.Client{
				Net:       "tcp-tls",
				TLSConfig: &tls.Config{InsecureSkipVerify: true},
				Timeout:   2 * time.Second,
			}
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(fmt.Sprintf("domain-%d.com", id)), dns.TypeA)
			r, _, err := client.Exchange(m, l.Addr().String())
			if err != nil {
				t.Errorf("[Goroutine %d] Exchange failed: %v", id, err)
				return
			}
			if r.Rcode != dns.RcodeSuccess {
				t.Errorf("[Goroutine %d] Expected Success, got %d", id, r.Rcode)
			}
		}(i)
	}
	wg.Wait()
}

func TestDoTHandlerPanicRecovery(t *testing.T) {
	// Giả lập một panic xảy ra khi gọi a.risk.Policy do a.risk = nil
	app := &app{
		risk:           nil, // Gây panic nil pointer dereference khi xử lý
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
	}

	selfCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{selfCert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	dotServer := &dns.Server{
		Listener: l,
		Net:      "tcp-tls",
		Handler:  dns.HandlerFunc(app.dotHandler),
	}
	go func() { _ = dotServer.ActivateAndServe() }()
	defer func() { _ = dotServer.Shutdown() }()

	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Timeout:   2 * time.Second,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	r, _, err := client.Exchange(m, l.Addr().String())
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	// Đảm bảo Rcode là RcodeServerFailure do panic được recover
	if r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected RcodeServerFailure due to panic, got %s", dns.RcodeToString[r.Rcode])
	}
}

func TestDoTHandlerIPv6Sanitization(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := readDNSMessage(w, r)
		query := new(dns.Msg)
		_ = query.Unpack(wire)
		resp := new(dns.Msg)
		resp.SetReply(query)
		respWire, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(respWire)
	}))
	defer mockUpstream.Close()

	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		upstreamDoHURL: mockUpstream.URL,
		upstreamClient: mockUpstream.Client(),
		blockPageIP:    "127.0.0.1",
		dnsTTL:         60,
		dotLimiter:     ratelimit.New(100, 10),
	}
	defer func() {
		_ = app.risk.Close()
		app.dotLimiter.Close()
	}()

	// Tạo một mock ResponseWriter với IP IPv6 dạng [::1] (hoặc địa chỉ có dấu ngoặc)
	mockWriter := &mockDNSWriter{remoteAddr: &mockAddr{net: "tcp", addr: "[::1]:12345"}}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	app.dotHandler(mockWriter, m)

	if mockWriter.writtenMsg == nil {
		t.Fatal("expected message to be written")
	}

	if mockWriter.writtenMsg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", mockWriter.writtenMsg.Rcode)
	}
}

type mockDNSWriter struct {
	remoteAddr net.Addr
	writtenMsg *dns.Msg
}

func (m *mockDNSWriter) LocalAddr() net.Addr  { return nil }
func (m *mockDNSWriter) RemoteAddr() net.Addr { return m.remoteAddr }
func (m *mockDNSWriter) WriteMsg(msg *dns.Msg) error {
	m.writtenMsg = msg
	return nil
}
func (m *mockDNSWriter) Write(p []byte) (int, error) { return 0, nil }
func (m *mockDNSWriter) Close() error                { return nil }
func (m *mockDNSWriter) TsigStatus() error           { return nil }
func (m *mockDNSWriter) TsigTimersOnly(bool)         {}
func (m *mockDNSWriter) Hijack()                     {}

type mockAddr struct {
	net  string
	addr string
}

func (a *mockAddr) Network() string { return a.net }
func (a *mockAddr) String() string  { return a.addr }
