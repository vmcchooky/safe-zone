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
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
}

func readAllLimited(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, doh.MaxDNSMessageSize))
}

// newPipelineResolver dựng một Resolver hoàn chỉnh với store SQLite tạm,
// mock upstream và block strategy sinkhole.
func newPipelineResolver(t *testing.T, upstreamURL string) (*Resolver, *store.DB, *observability.Registry) {
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
	upstreams := doh.NewUpstreamResolver(upstreamURL, http.DefaultClient)
	resolverInstance := New(riskService, metrics, upstreams, Config{
		BlockPageIP:    testBlockPageIP,
		BlockStrategy:  BlockStrategySinkhole,
		DNSTTL:         60,
		DeploymentTier: "budget-vps",
	}, nil)
	return resolverInstance, storeDB, metrics
}

func TestResolveQueryForwardsAllowedDomain(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	r, _, _ := newPipelineResolver(t, upstream.URL)

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

func TestResolveQueryBlocksOverriddenDomain(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	r, storeDB, _ := newPipelineResolver(t, upstream.URL)
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
	r, storeDB, _ := newPipelineResolver(t, upstream.URL)
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
	r, _, metrics := newPipelineResolver(t, deadUpstream.URL)

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
	r, storeDB, _ := newPipelineResolver(t, upstream.URL)
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
