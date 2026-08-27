package doh

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockUpstream trả về một httptest server phục vụ wire DNS qua HTTP với
// Content-Type chuẩn RFC 8484.
func mockUpstream(t *testing.T, status int, contentType string, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != ContentTypeDNSMessage {
			t.Errorf("upstream expected Content-Type %s, got %q", ContentTypeDNSMessage, got)
		}
		if got := r.Header.Get("Accept"); got != ContentTypeDNSMessage {
			t.Errorf("upstream expected Accept %s, got %q", ContentTypeDNSMessage, got)
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

func TestExchangeReturnsUpstreamAnswer(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	response := testAAnswer("example.com", "93.184.216.34", 120)
	server := mockUpstream(t, http.StatusOK, ContentTypeDNSMessage, wireOf(t, response))
	defer server.Close()

	got, err := Exchange(context.Background(), server.Client(), server.URL, wireOf(t, query))
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	parsed := new(dns.Msg)
	if err := parsed.Unpack(got); err != nil {
		t.Fatalf("unpack upstream response: %v", err)
	}
	if len(parsed.Answer) != 1 || parsed.Answer[0].Header().Ttl != 120 {
		t.Fatalf("unexpected upstream response: %v", parsed)
	}
}

func TestExchangeRejectsUnexpectedContentType(t *testing.T) {
	// Một captive portal hoặc proxy có thể trả 200 với HTML; exchange phải
	// coi đó là lỗi upstream thay vì để Unpack hỏng ở tầng sau.
	query := testQuery(t, "example.com", dns.TypeA)
	server := mockUpstream(t, http.StatusOK, "text/html", []byte("<html>portal</html>"))
	defer server.Close()

	if _, err := Exchange(context.Background(), server.Client(), server.URL, wireOf(t, query)); err == nil {
		t.Fatal("expected error for HTML response body")
	} else if !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("expected content-type error, got %v", err)
	}
}

func TestExchangeRejectsHTTPErrorStatus(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	server := mockUpstream(t, http.StatusBadGateway, ContentTypeDNSMessage, []byte("upstream down"))
	defer server.Close()

	if _, err := Exchange(context.Background(), server.Client(), server.URL, wireOf(t, query)); err == nil {
		t.Fatal("expected error for HTTP 502")
	}
}

func TestExchangeRejectsOversizedResponse(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	server := mockUpstream(t, http.StatusOK, ContentTypeDNSMessage, bytes.Repeat([]byte{0x00}, MaxDNSMessageSize+1))
	defer server.Close()

	_, err := Exchange(context.Background(), server.Client(), server.URL, wireOf(t, query))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func TestUpstreamResolverFailsOverToHealthyEndpoint(t *testing.T) {
	deadServer := mockUpstream(t, http.StatusInternalServerError, ContentTypeDNSMessage, nil)
	defer deadServer.Close()
	healthyServer := mockUpstream(t, http.StatusOK, ContentTypeDNSMessage, wireOf(t, testAAnswer("example.com", "1.1.1.1", 60)))
	defer healthyServer.Close()

	// NewUpstreamResolver nhận danh sách URL phân tách bởi dấu phẩy, thứ tự
	// giữ nguyên nên endpoint đầu tiên là dead server.
	pool := NewUpstreamResolver(deadServer.URL+","+healthyServer.URL, healthyServer.Client())

	wire := wireOf(t, testQuery(t, "example.com", dns.TypeA))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, activeURL, err := pool.Forward(ctx, wire)
	if err != nil {
		t.Fatalf("forward failed: %v", err)
	}
	if activeURL != healthyServer.URL {
		t.Fatalf("expected failover to healthy endpoint, got %s", activeURL)
	}
	parsed := new(dns.Msg)
	if err := parsed.Unpack(got); err != nil {
		t.Fatalf("unpack response: %v", err)
	}

	status := pool.Status()
	endpoints := status["endpoints"].([]UpstreamEndpoint)
	if endpoints[0].URL != healthyServer.URL || !endpoints[0].Healthy {
		t.Fatalf("healthy endpoint should sort first after failover: %#v", endpoints)
	}
	if endpoints[1].URL != deadServer.URL || endpoints[1].Healthy || endpoints[1].Failures != 1 {
		t.Fatalf("dead endpoint should be marked unhealthy: %#v", endpoints)
	}
}

func TestUpstreamResolverFailsWhenAllEndpointsDown(t *testing.T) {
	dead1 := mockUpstream(t, http.StatusInternalServerError, ContentTypeDNSMessage, nil)
	defer dead1.Close()
	dead2 := mockUpstream(t, http.StatusServiceUnavailable, ContentTypeDNSMessage, nil)
	defer dead2.Close()

	pool := NewUpstreamResolver(dead1.URL+","+dead2.URL, dead1.Client())
	if _, _, err := pool.Forward(context.Background(), wireOf(t, testQuery(t, "example.com", dns.TypeA))); err == nil {
		t.Fatal("expected error when all upstream endpoints fail")
	}
}

func TestUpstreamResolverDefaultsToCloudflare(t *testing.T) {
	pool := NewUpstreamResolver("  ", nil)
	if got := pool.PrimaryURL(); got != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("expected default cloudflare upstream, got %s", got)
	}
}
