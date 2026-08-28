package doh

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"safe-zone/internal/netguard"
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

// policyUpstream rewrites a loopback httptest URL to a public RFC 5737
// documentation IP so the exchange passes the outbound policy checks, while
// the returned client still dials the real loopback listener. This keeps
// end-to-end HTTP behavior and exercises the same validation path as
// production traffic.
func policyUpstream(t *testing.T, srv *httptest.Server) (string, *http.Client) {
	t.Helper()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest url: %v", err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split httptest host: %v", err)
	}
	publicURL := "http://" + net.JoinHostPort("198.51.100.10", port) + parsed.Path
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
	return publicURL, client
}

func TestExchangeReturnsUpstreamAnswer(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	response := testAAnswer("example.com", "93.184.216.34", 120)
	server := mockUpstream(t, http.StatusOK, ContentTypeDNSMessage, wireOf(t, response))
	defer server.Close()

	upstreamURL, upstreamClient := policyUpstream(t, server)
	got, err := Exchange(context.Background(), upstreamClient, upstreamURL, wireOf(t, query))
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

	upstreamURL, upstreamClient := policyUpstream(t, server)
	if _, err := Exchange(context.Background(), upstreamClient, upstreamURL, wireOf(t, query)); err == nil {
		t.Fatal("expected error for HTML response body")
	} else if !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("expected content-type error, got %v", err)
	}
}

func TestExchangeRejectsHTTPErrorStatus(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	server := mockUpstream(t, http.StatusBadGateway, ContentTypeDNSMessage, []byte("upstream down"))
	defer server.Close()

	upstreamURL, upstreamClient := policyUpstream(t, server)
	if _, err := Exchange(context.Background(), upstreamClient, upstreamURL, wireOf(t, query)); err == nil {
		t.Fatal("expected error for HTTP 502")
	}
}

func TestExchangeRejectsOversizedResponse(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	server := mockUpstream(t, http.StatusOK, ContentTypeDNSMessage, bytes.Repeat([]byte{0x00}, MaxDNSMessageSize+1))
	defer server.Close()

	upstreamURL, upstreamClient := policyUpstream(t, server)
	_, err := Exchange(context.Background(), upstreamClient, upstreamURL, wireOf(t, query))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func TestExchangeRejectsBlockedUpstreamURLs(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	wire := wireOf(t, query)

	tests := []struct {
		name string
		url  string
	}{
		{"loopback literal", "http://127.0.0.1:5335/dns-query"},
		{"private literal", "http://192.168.1.2/dns-query"},
		{"CGNAT literal", "http://100.64.0.1/dns-query"},
		{"link-local metadata", "http://169.254.169.254/latest/meta-data/"},
		{"localhost hostname", "http://localhost:5335/dns-query"},
		{"non-HTTP scheme", "ftp://example.com/dns-query"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Không client nào được truyền: validation phải chặn trước khi
			// bất kỳ I/O nào xảy ra.
			if _, err := Exchange(context.Background(), nil, tt.url, wire); err == nil {
				t.Fatalf("expected upstream URL %q to be rejected", tt.url)
			}
		})
	}
}

func TestExchangeRejectsRedirectToBlockedTarget(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect từ upstream "hợp lệ" sang đích bị cấm (CGNAT). Exchange
		// phải từ chối với lỗi rõ ràng, không theo và không coi 302 là thành công.
		http.Redirect(w, r, "http://100.64.0.1/dns-query", http.StatusFound)
	}))
	defer server.Close()

	upstreamURL, upstreamClient := policyUpstream(t, server)
	_, err := Exchange(context.Background(), upstreamClient, upstreamURL, wireOf(t, query))
	if err == nil {
		t.Fatal("expected redirect to blocked target to fail the exchange")
	}
	if !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got %v", err)
	}
}

func TestExchangeFollowsRedirectToAllowedTarget(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	response := testAAnswer("example.com", "93.184.216.34", 120)

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) == 1 {
			// Redirect hop trỏ về chính endpoint public-mapped (r.Host là
			// 198.51.100.10:port) — hợp lệ theo policy nên phải được theo.
			http.Redirect(w, r, "http://"+r.Host+r.URL.Path, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", ContentTypeDNSMessage)
		_, _ = w.Write(wireOf(t, response))
	}))
	defer server.Close()

	upstreamURL, upstreamClient := policyUpstream(t, server)
	got, err := Exchange(context.Background(), upstreamClient, upstreamURL, wireOf(t, query))
	if err != nil {
		t.Fatalf("expected valid redirect to be followed, got %v", err)
	}
	parsed := new(dns.Msg)
	if err := parsed.Unpack(got); err != nil {
		t.Fatalf("unpack upstream response: %v", err)
	}
	if atomic.LoadInt32(&requests) != 2 {
		t.Fatalf("expected 2 requests (initial + redirect), got %d", requests)
	}
}

func TestExchangeRejectsRedirectToLoopbackTarget(t *testing.T) {
	query := testQuery(t, "example.com", dns.TypeA)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9/dns-query", http.StatusFound)
	}))
	defer server.Close()

	upstreamURL, upstreamClient := policyUpstream(t, server)
	if _, err := Exchange(context.Background(), upstreamClient, upstreamURL, wireOf(t, query)); err == nil {
		t.Fatal("expected redirect to loopback to fail the exchange")
	}
}

func TestUpstreamResolverFailsOverToHealthyEndpoint(t *testing.T) {
	deadServer := mockUpstream(t, http.StatusInternalServerError, ContentTypeDNSMessage, nil)
	defer deadServer.Close()
	healthyServer := mockUpstream(t, http.StatusOK, ContentTypeDNSMessage, wireOf(t, testAAnswer("example.com", "1.1.1.1", 60)))
	defer healthyServer.Close()

	// NewUpstreamResolver nhận danh sách URL phân tách bởi dấu phẩy, thứ tự
	// giữ nguyên nên endpoint đầu tiên là dead server.
	deadURL, _ := policyUpstream(t, deadServer)
	healthyURL, upstreamClient := policyUpstream(t, healthyServer)
	pool := NewUpstreamResolver(deadURL+","+healthyURL, upstreamClient)

	wire := wireOf(t, testQuery(t, "example.com", dns.TypeA))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, activeURL, err := pool.Forward(ctx, wire)
	if err != nil {
		t.Fatalf("forward failed: %v", err)
	}
	if activeURL != healthyURL {
		t.Fatalf("expected failover to healthy endpoint, got %s", activeURL)
	}
	parsed := new(dns.Msg)
	if err := parsed.Unpack(got); err != nil {
		t.Fatalf("unpack response: %v", err)
	}

	status := pool.Status()
	endpoints := status["endpoints"].([]UpstreamEndpoint)
	if endpoints[0].URL != healthyURL || !endpoints[0].Healthy {
		t.Fatalf("healthy endpoint should sort first after failover: %#v", endpoints)
	}
	if endpoints[1].URL != deadURL || endpoints[1].Healthy || endpoints[1].Failures != 1 {
		t.Fatalf("dead endpoint should be marked unhealthy: %#v", endpoints)
	}
}

func TestUpstreamResolverFailsWhenAllEndpointsDown(t *testing.T) {
	dead1 := mockUpstream(t, http.StatusInternalServerError, ContentTypeDNSMessage, nil)
	defer dead1.Close()
	dead2 := mockUpstream(t, http.StatusServiceUnavailable, ContentTypeDNSMessage, nil)
	defer dead2.Close()

	dead1URL, upstreamClient := policyUpstream(t, dead1)
	dead2URL, _ := policyUpstream(t, dead2)
	pool := NewUpstreamResolver(dead1URL+","+dead2URL, upstreamClient)
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

func TestExchangeGuardsSharedClientUnmodified(t *testing.T) {
	// Exchange phải không đính CheckRedirect vào client do caller truyền vào
	// (client được UpstreamResolver dùng chung lâu dài).
	server := mockUpstream(t, http.StatusOK, ContentTypeDNSMessage, wireOf(t, testAAnswer("example.com", "1.1.1.1", 60)))
	defer server.Close()

	upstreamURL, upstreamClient := policyUpstream(t, server)
	if _, err := Exchange(context.Background(), upstreamClient, upstreamURL, wireOf(t, testQuery(t, "example.com", dns.TypeA))); err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if upstreamClient.CheckRedirect != nil {
		t.Fatal("Exchange must not mutate the caller's client redirect policy")
	}
}
