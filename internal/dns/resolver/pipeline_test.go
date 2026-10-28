package resolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"safe-zone/internal/config"
	"safe-zone/internal/dns/doh"
	"safe-zone/internal/observability"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

const (
	testBlockPageIP = "127.0.0.1"
	testForwardedIP = "93.184.216.34"
	testAnswerTTL   = 120
)

// echoUpstream mô phỏng upstream DoH: trả lời mọi truy vấn A bằng địa chỉ
// cài sẵn; truy vấn "cname.example" trả CNAME trỏ tới "blocked-target.example"
// để kiểm tra uncloaking.
func echoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(echoUpstreamHandler(t))
}

func echoUpstreamHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := readAllLimited(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			http.Error(w, "invalid dns message", http.StatusBadRequest)
			return
		}
		response := new(dns.Msg)
		response.SetReply(query)
		if query.Question[0].Name == "cname.example." {
			response.Answer = append(response.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: testAnswerTTL},
				Target: "blocked-target.example.",
			})
		} else {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: testAnswerTTL},
				A:   net.ParseIP(testForwardedIP),
			})
		}
		respWire, err := response.Pack()
		if err != nil {
			t.Errorf("pack upstream response: %v", err)
			return
		}
		w.Header().Set("Content-Type", doh.ContentTypeDNSMessage)
		_, _ = w.Write(respWire)
	})
}

func readAllLimited(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, doh.MaxDNSMessageSize))
}

// policyUpstream rewrites a loopback httptest URL to a public RFC 5737
// documentation IP so the upstream passes the outbound policy checks, while
// the returned client still dials the real loopback listener — the same
// validation path production traffic takes.
func policyUpstream(t *testing.T, srv *httptest.Server) (string, *http.Client) {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		t.Fatalf("split upstream host: %v", err)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, dialPort, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", dialPort))
			},
		},
	}
	return "http://" + net.JoinHostPort("198.51.100.10", port), client
}

// newPipelineResolver dựng một Resolver hoàn chỉnh với store SQLite tạm,
// mock upstream và block strategy sinkhole.
func newPipelineResolver(t *testing.T, upstreamURL string, upstreamClient *http.Client) (*Resolver, *store.DB, *observability.Registry) {
	t.Helper()
	return newPipelineResolverWithCache(t, upstreamURL, upstreamClient, 0)
}

func newPipelineResolverWithCache(t *testing.T, upstreamURL string, upstreamClient *http.Client, cacheEntries int) (*Resolver, *store.DB, *observability.Registry) {
	t.Helper()
	storeDB, err := store.New(filepath.Join(t.TempDir(), "pipeline.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	riskService := risk.NewService(risk.Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		RedisTimeout:   10 * time.Millisecond,
		Store:          storeDB,
	})
	t.Cleanup(func() { _ = riskService.Close() })

	metrics := observability.NewRegistry()
	upstreams := doh.NewUpstreamResolver(upstreamURL, upstreamClient)
	resolverInstance := New(riskService, metrics, upstreams, Config{
		BlockPageIP:     testBlockPageIP,
		BlockStrategy:   BlockStrategySinkhole,
		DNSTTL:          60,
		DeploymentTier:  "budget-vps",
		DNSCacheEntries: cacheEntries,
	}, nil)
	return resolverInstance, storeDB, metrics
}

func TestResolveQueryForwardsAllowedDomain(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, _, _ := newPipelineResolver(t, upstreamURL, upstreamClient)

	response, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "example.com"), doh.ClientInfo{IP: "192.168.1.10"})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(response.Answer))
	}
	aRecord, ok := response.Answer[0].(*dns.A)
	if !ok || aRecord.A.String() != testForwardedIP {
		t.Fatalf("expected forwarded A %s, got %#v", testForwardedIP, response.Answer[0])
	}
}

func TestResolveQueryServesRepeatedQuestionFromCache(t *testing.T) {
	handler := echoUpstreamHandler(t)
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		handler.ServeHTTP(w, r)
	}))
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, _, metrics := newPipelineResolverWithCache(t, upstreamURL, upstreamClient, 16)

	first := testPipelineQuery(t, "example.com")
	first.Id = 100
	if _, err := r.ResolveQuery(context.Background(), first, doh.ClientInfo{IP: "192.168.1.10"}); err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}

	second := testPipelineQuery(t, "example.com")
	second.Id = 200
	response, err := r.ResolveQuery(context.Background(), second, doh.ClientInfo{IP: "192.168.1.10"})
	if err != nil {
		t.Fatalf("cached resolve failed: %v", err)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d; want 1", got)
	}
	if response.Id != second.Id {
		t.Fatalf("cached response ID = %d; want %d", response.Id, second.Id)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(response.Answer))
	}
	if ttl := response.Answer[0].Header().Ttl; ttl > testAnswerTTL {
		t.Fatalf("cached TTL = %d; want <= %d", ttl, testAnswerTTL)
	}

	counters := metrics.Snapshot().Counters
	if counters["dns_cache_hits_total"] != 1 || counters["dns_cache_misses_total"] != 1 {
		t.Fatalf("cache counters = hits %d, misses %d; want 1,1",
			counters["dns_cache_hits_total"], counters["dns_cache_misses_total"])
	}
}

func TestResolveQueryRechecksQuestionPolicyOnCacheHit(t *testing.T) {
	handler := echoUpstreamHandler(t)
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		handler.ServeHTTP(w, r)
	}))
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, storeDB, _ := newPipelineResolverWithCache(t, upstreamURL, upstreamClient, 16)

	if _, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "example.com"), doh.ClientInfo{IP: "192.168.1.10"}); err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	if err := storeDB.UpsertOverride(context.Background(), "example.com", "block", "added after cache"); err != nil {
		t.Fatal(err)
	}

	response, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "example.com"), doh.ClientInfo{IP: "192.168.1.10"})
	if err != nil {
		t.Fatalf("second resolve failed: %v", err)
	}
	aRecord, ok := response.Answer[0].(*dns.A)
	if !ok || aRecord.A.String() != testBlockPageIP {
		t.Fatalf("expected the new block policy on a cache hit, got %#v", response.Answer)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d; want 1 (the second answer must come from cache)", got)
	}
}

func TestResolveQueryRechecksCNAMEPolicyOnCacheHit(t *testing.T) {
	handler := echoUpstreamHandler(t)
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		handler.ServeHTTP(w, r)
	}))
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, storeDB, _ := newPipelineResolverWithCache(t, upstreamURL, upstreamClient, 16)

	if _, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "cname.example"), doh.ClientInfo{IP: "192.168.1.10"}); err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	if err := storeDB.UpsertOverride(context.Background(), "blocked-target.example", "block", "added after cache"); err != nil {
		t.Fatal(err)
	}

	response, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "cname.example"), doh.ClientInfo{IP: "192.168.1.10"})
	if err != nil {
		t.Fatalf("second resolve failed: %v", err)
	}
	aRecord, ok := response.Answer[0].(*dns.A)
	if !ok || aRecord.A.String() != testBlockPageIP {
		t.Fatalf("expected CNAME uncloaking on a cache hit, got %#v", response.Answer)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d; want 1 (the CNAME answer must come from cache)", got)
	}
}

func TestResolveQueryBlocksOverriddenDomain(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, storeDB, _ := newPipelineResolver(t, upstreamURL, upstreamClient)
	if err := storeDB.UpsertOverride(context.Background(), "blocked.example", "block", "test override"); err != nil {
		t.Fatal(err)
	}

	response, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "blocked.example"), doh.ClientInfo{IP: "192.168.1.10"})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected sinkhole answer, got %d answers", len(response.Answer))
	}
	aRecord, ok := response.Answer[0].(*dns.A)
	if !ok || aRecord.A.String() != testBlockPageIP {
		t.Fatalf("expected block page IP %s, got %#v", testBlockPageIP, response.Answer[0])
	}
	if aRecord.Hdr.Ttl != 60 {
		t.Fatalf("expected block TTL 60, got %d", aRecord.Hdr.Ttl)
	}
}

func TestResolveQueryUncloaksBlockedCNAMETarget(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, storeDB, _ := newPipelineResolver(t, upstreamURL, upstreamClient)
	// Tên miền được hỏi (cname.example) sạch, nhưng đích CNAME bị chặn:
	// pipeline phải uncloak và trả block page.
	if err := storeDB.UpsertOverride(context.Background(), "blocked-target.example", "block", "cname target"); err != nil {
		t.Fatal(err)
	}

	response, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "cname.example"), doh.ClientInfo{IP: "192.168.1.10"})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected sinkhole answer, got %d answers", len(response.Answer))
	}
	aRecord, ok := response.Answer[0].(*dns.A)
	if !ok || aRecord.A.String() != testBlockPageIP {
		t.Fatalf("expected block page IP %s after uncloaking, got %#v", testBlockPageIP, response.Answer[0])
	}
}

func TestResolveQueryCountsUpstreamFailures(t *testing.T) {
	deadUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadUpstream.Close() // đóng ngay để mô phỏng upstream sập
	// Upstream loopback bây giờ bị outbound policy chặn ngay từ bước
	// validate — vẫn tính là upstream failure cho metrics.
	r, _, metrics := newPipelineResolver(t, deadUpstream.URL, http.DefaultClient)

	if _, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "example.com"), doh.ClientInfo{IP: "192.168.1.10"}); err == nil {
		t.Fatal("expected upstream failure error")
	}
	if got := metrics.Snapshot().Counters["upstream_doh_failures_total"]; got != 1 {
		t.Fatalf("expected upstream_doh_failures_total=1, got %d", got)
	}
}

// TestDoTHandlerEndToEnd xác nhận transport DoT vẫn hoạt động trên pipeline
// dùng chung: cho phép domain sạch, chặn domain override.
func TestDoTHandlerEndToEnd(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, storeDB, _ := newPipelineResolver(t, upstreamURL, upstreamClient)
	if err := storeDB.UpsertOverride(context.Background(), "bocongan-verify.xyz", "block", "mock malicious site"); err != nil {
		t.Fatal(err)
	}

	cert := testTLSCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	dotServer := &dns.Server{Listener: listener, Net: "tcp-tls", Handler: dns.HandlerFunc(r.DoTHandler)}
	go func() { _ = dotServer.ActivateAndServe() }()
	defer func() { _ = dotServer.Shutdown() }()

	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test local với cert tự ký
		Timeout:   3 * time.Second,
	}

	t.Run("allow forwards to upstream", func(t *testing.T) {
		msg := testPipelineQuery(t, "example.com")
		response, _, err := client.Exchange(msg, listener.Addr().String())
		if err != nil {
			t.Fatalf("DoT exchange failed: %v", err)
		}
		aRecord, ok := response.Answer[0].(*dns.A)
		if !ok || aRecord.A.String() != testForwardedIP {
			t.Fatalf("expected forwarded answer %s, got %#v", testForwardedIP, response.Answer)
		}
	})

	t.Run("block returns block page IP", func(t *testing.T) {
		msg := testPipelineQuery(t, "bocongan-verify.xyz")
		response, _, err := client.Exchange(msg, listener.Addr().String())
		if err != nil {
			t.Fatalf("DoT exchange failed: %v", err)
		}
		aRecord, ok := response.Answer[0].(*dns.A)
		if !ok || aRecord.A.String() != testBlockPageIP {
			t.Fatalf("expected block page IP, got %#v", response.Answer)
		}
	})
}

func testPipelineQuery(t *testing.T, name string) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return query
}

// testTLSCertificate sinh chứng chỉ ECDSA tự ký dùng riêng cho test DoT.
func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pipeline.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
