package resolver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
	"safe-zone/internal/dns/doh"
	"safe-zone/internal/observability"
	"safe-zone/internal/ratelimit"
	"safe-zone/internal/risk"
	"safe-zone/internal/serve"
)

func newStatusTestResolver(t *testing.T) (*Resolver, *observability.Registry) {
	t.Helper()
	r, _, metrics := newPipelineResolver(t, "https://cloudflare-dns.com/dns-query", http.DefaultClient)
	return r, metrics
}

// testDNSQuery tạo câu truy vấn DNS với qtype tùy ý (bản 2 tham số của
// testPipelineQuery chỉ dùng cho TypeA trong pipeline_test.go).
func testDNSQuery(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), qtype)
	return query
}

func TestStatusHandlerRoot(t *testing.T) {
	r, _ := newStatusTestResolver(t)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	r.StatusHandler(recorder, request)

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
	r, _ := newStatusTestResolver(t)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/status", nil)

	r.StatusHandler(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}

func TestMetricsHandlerRoot(t *testing.T) {
	r, metrics := newStatusTestResolver(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", r.MetricsHandler)
	testServer := httptest.NewServer(serve.WithRequestID(httputil.LogRequests("dns-resolver", metrics)(mux)))
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
	metricsPayload, ok := payload["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected metrics object, got %#v", payload["metrics"])
	}
	if _, ok := metricsPayload["request_summary"].(map[string]any); !ok {
		t.Fatalf("expected request_summary map, got %#v", metricsPayload["request_summary"])
	}
	redisStatus, ok := payload["redis"].(map[string]any)
	if !ok {
		t.Fatalf("expected redis status object, got %#v", payload["redis"])
	}
	if redisStatus["status"] != "disabled" {
		t.Fatalf("expected disabled redis status, got %#v", redisStatus["status"])
	}
}

func TestVersionHandlerReportsBuildMetadata(t *testing.T) {
	restore := overrideResolverBuildInfo("1.3.0", "abc123def", "2026-05-26T12:00:00Z", "safe-zone-dns-resolver:1.3.0-abc123def", "https://github.com/quorix/safe-zone")
	defer restore()

	r := &Resolver{Config: Config{DeploymentTier: "shared-vps"}}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	r.VersionHandler(recorder, request)

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
	r := &Resolver{Config: Config{DeploymentTier: "budget-vps"}}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/version", nil)
	r.VersionHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", recorder.Code)
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
			strategy:      BlockStrategySinkhole,
			qtype:         dns.TypeA,
			expectedRcode: dns.RcodeSuccess,
			expectedIP:    "203.0.113.10",
			expectedType:  dns.TypeA,
		},
		{
			name:          "nxdomain returns name error without answers",
			strategy:      BlockStrategyNXDomain,
			qtype:         dns.TypeA,
			expectedRcode: dns.RcodeNameError,
		},
		{
			name:          "refused returns refused without answers",
			strategy:      BlockStrategyRefused,
			qtype:         dns.TypeA,
			expectedRcode: dns.RcodeRefused,
		},
		{
			name:          "nullip A returns IPv4 null address",
			strategy:      BlockStrategyNullIP,
			qtype:         dns.TypeA,
			expectedRcode: dns.RcodeSuccess,
			expectedIP:    "0.0.0.0",
			expectedType:  dns.TypeA,
		},
		{
			name:          "nullip AAAA returns IPv6 null address",
			strategy:      BlockStrategyNullIP,
			qtype:         dns.TypeAAAA,
			expectedRcode: dns.RcodeSuccess,
			expectedIP:    "::",
			expectedType:  dns.TypeAAAA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Resolver{Config: Config{BlockPageIP: "203.0.113.10", BlockStrategy: tt.strategy, DNSTTL: 60}}
			query := testDNSQuery(t, "blocked.example", tt.qtype)

			response, err := r.BlockedDNSMessage(query)
			if err != nil {
				t.Fatalf("BlockedDNSMessage failed: %v", err)
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

// TestPolicyHandlerGroupMapping xác nhận policy endpoint phân giải client từ
// proxy header (Caddy edge) tới group mapping trong store.
func TestPolicyHandlerGroupMapping(t *testing.T) {
	r, _, _ := newPipelineResolver(t, "https://cloudflare-dns.com/dns-query", http.DefaultClient)
	db := r.Risk.StoreDB()

	adultGroupID, err := db.CreateGroup(context.Background(), "adult-blocker", "Blocks adult content", []string{"adult"}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMappingInt(context.Background(), "ip", "192.168.2.10", adultGroupID); err != nil {
		t.Fatal(err)
	}

	// Case 1: IP mapped vào group chặn nội dung adult.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/policy?domain=xvideos.porn", nil)
	// httptest đặt RemoteAddr ngoài dải trusted proxy; mô phỏng Caddy edge
	// bằng loopback để X-Forwarded-For được tin tưởng.
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("X-Forwarded-For", "192.168.2.10")

	r.PolicyHandler(recorder, request)

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

	// Case 2: IP không mapped → group mặc định → allow.
	recorderDefault := httptest.NewRecorder()
	requestDefault := httptest.NewRequest(http.MethodGet, "/v1/policy?domain=xvideos.porn", nil)
	requestDefault.RemoteAddr = "127.0.0.1:54321"
	requestDefault.Header.Set("X-Forwarded-For", "192.168.2.20")

	r.PolicyHandler(recorderDefault, requestDefault)

	var payloadDefault policyResponse
	if err := json.NewDecoder(recorderDefault.Body).Decode(&payloadDefault); err != nil {
		t.Fatal(err)
	}
	if payloadDefault.Policy.Policy != "allow" {
		t.Fatalf("expected allow policy for default group client, got %s", payloadDefault.Policy.Policy)
	}
}

// newDoTTestResolver dựng resolver hoàn chỉnh với upstream chỉ định và DoT
// rate limiter, phục vụ các test transport DoT.
func newDoTTestResolver(t *testing.T, upstreamURL string, upstreamClient *http.Client, limiter *ratelimit.Limiter) *Resolver {
	t.Helper()
	riskService := risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond})
	t.Cleanup(func() { _ = riskService.Close() })
	return New(riskService, observability.NewRegistry(), doh.NewUpstreamResolver(upstreamURL, upstreamClient), Config{
		BlockPageIP:   testBlockPageIP,
		BlockStrategy: BlockStrategySinkhole,
		DNSTTL:        60,
	}, limiter)
}

// startDoTTestServer lắng nghe TLS loopback với handler DoT của resolver.
func startDoTTestServer(t *testing.T, r *Resolver) (string, *dns.Server) {
	t.Helper()
	cert := testTLSCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	dotServer := &dns.Server{Listener: listener, Net: "tcp-tls", Handler: dns.HandlerFunc(r.DoTHandler)}
	go func() { _ = dotServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = dotServer.Shutdown() })
	return listener.Addr().String(), dotServer
}

func dotTestClient() *dns.Client {
	return &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test local với cert tự ký
		Timeout:   3 * time.Second,
	}
}

func TestDoTHandlerRateLimiter(t *testing.T) {
	deadUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadUpstream.Close() // đóng ngay: truy vấn nào lọt qua limiter sẽ SERVFAIL thay vì panic

	limiter := ratelimit.New(0.1, 0) // cực kỳ hạn chế
	defer limiter.Close()

	r := newDoTTestResolver(t, deadUpstream.URL, http.DefaultClient, limiter)
	addr, _ := startDoTTestServer(t, r)
	client := dotTestClient()

	m := testDNSQuery(t, "example.com", dns.TypeA)
	// Cuộc gọi đầu tiên có thể được chấp nhận hoặc bị từ chối tùy burst = 0,
	// nhưng cuộc gọi thứ hai liên tiếp chắc chắn bị từ chối (RPM = 0.1).
	_, _, _ = client.Exchange(m, addr)
	response, _, err := client.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DoT exchange failed: %v", err)
	}
	if response.Rcode != dns.RcodeRefused {
		t.Fatalf("expected RcodeRefused due to rate limit, got %s", dns.RcodeToString[response.Rcode])
	}
}

func TestDoTHandlerConcurrent(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()

	limiter := ratelimit.New(1000, 100)
	defer limiter.Close()

	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r := newDoTTestResolver(t, upstreamURL, upstreamClient, limiter)
	addr, _ := startDoTTestServer(t, r)
	client := dotTestClient()

	var wg sync.WaitGroup
	concurrentRequests := 10
	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			m := testDNSQuery(t, "domain-"+strconv.Itoa(id)+".example", dns.TypeA)
			response, _, err := client.Exchange(m, addr)
			if err != nil {
				t.Errorf("[Goroutine %d] Exchange failed: %v", id, err)
				return
			}
			if response.Rcode != dns.RcodeSuccess {
				t.Errorf("[Goroutine %d] Expected Success, got %d", id, response.Rcode)
			}
		}(i)
	}
	wg.Wait()
}

func TestDoTHandlerPanicRecovery(t *testing.T) {
	// Risk nil gây panic nil-pointer bên trong pipeline; handler phải recover
	// và trả SERVFAIL thay vì làm sập server.
	r := &Resolver{Metrics: observability.NewRegistry()}

	writer := &mockDNSWriter{remoteAddr: &mockAddr{net: "tcp", addr: "127.0.0.1:9999"}}
	r.DoTHandler(writer, testDNSQuery(t, "example.com", dns.TypeA))

	if writer.writtenMsg == nil {
		t.Fatal("expected SERVFAIL message to be written")
	}
	if writer.writtenMsg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected RcodeServerFailure due to panic, got %s", dns.RcodeToString[writer.writtenMsg.Rcode])
	}
}

func TestDoTHandlerIPv6Sanitization(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, _, _ := newPipelineResolver(t, upstreamURL, upstreamClient)

	// RemoteAddr dạng [::1]:12345 phải được chuẩn hóa thành ::1 thay vì làm
	// hỏng policy lookup.
	writer := &mockDNSWriter{remoteAddr: &mockAddr{net: "tcp", addr: "[::1]:12345"}}
	r.DoTHandler(writer, testDNSQuery(t, "example.com", dns.TypeA))

	if writer.writtenMsg == nil {
		t.Fatal("expected message to be written")
	}
	if writer.writtenMsg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", writer.writtenMsg.Rcode)
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
